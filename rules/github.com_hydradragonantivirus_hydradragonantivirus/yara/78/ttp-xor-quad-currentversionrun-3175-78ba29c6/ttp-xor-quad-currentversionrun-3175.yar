rule TTP_XOR_QUAD_CurrentVersionRun_3175 {
  strings:
    $key_3175 = { 62 1a [2] 46 14 [2] 6d 38 [2] 43 1a [2] 57 01 [2] 58 1b [2] 46 06 [2] 44 07 [2] 5f 01 [2] 43 06 [2] 5f 29 }

  condition:
    any of them
}