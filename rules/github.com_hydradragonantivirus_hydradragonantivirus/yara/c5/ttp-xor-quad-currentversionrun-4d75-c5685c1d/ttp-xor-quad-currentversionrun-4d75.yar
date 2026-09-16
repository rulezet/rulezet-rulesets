rule TTP_XOR_QUAD_CurrentVersionRun_4d75 {
  strings:
    $key_4d75 = { 1e 1a [2] 3a 14 [2] 11 38 [2] 3f 1a [2] 2b 01 [2] 24 1b [2] 3a 06 [2] 38 07 [2] 23 01 [2] 3f 06 [2] 23 29 }

  condition:
    any of them
}