rule TTP_XOR_QUAD_CurrentVersionRun_4d25 {
  strings:
    $key_4d25 = { 1e 4a [2] 3a 44 [2] 11 68 [2] 3f 4a [2] 2b 51 [2] 24 4b [2] 3a 56 [2] 38 57 [2] 23 51 [2] 3f 56 [2] 23 79 }

  condition:
    any of them
}