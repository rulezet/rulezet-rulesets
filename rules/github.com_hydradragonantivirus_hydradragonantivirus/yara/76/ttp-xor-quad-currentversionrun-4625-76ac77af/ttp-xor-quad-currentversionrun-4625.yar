rule TTP_XOR_QUAD_CurrentVersionRun_4625 {
  strings:
    $key_4625 = { 15 4a [2] 31 44 [2] 1a 68 [2] 34 4a [2] 20 51 [2] 2f 4b [2] 31 56 [2] 33 57 [2] 28 51 [2] 34 56 [2] 28 79 }

  condition:
    any of them
}