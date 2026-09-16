rule TTP_XOR_QUAD_CurrentVersionRun_5d25 {
  strings:
    $key_5d25 = { 0e 4a [2] 2a 44 [2] 01 68 [2] 2f 4a [2] 3b 51 [2] 34 4b [2] 2a 56 [2] 28 57 [2] 33 51 [2] 2f 56 [2] 33 79 }

  condition:
    any of them
}