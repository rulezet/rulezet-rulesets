rule TTP_XOR_QUAD_CurrentVersionRun_4639 {
  strings:
    $key_4639 = { 15 56 [2] 31 58 [2] 1a 74 [2] 34 56 [2] 20 4d [2] 2f 57 [2] 31 4a [2] 33 4b [2] 28 4d [2] 34 4a [2] 28 65 }

  condition:
    any of them
}