rule TTP_XOR_QUAD_CurrentVersionRun_3169 {
  strings:
    $key_3169 = { 62 06 [2] 46 08 [2] 6d 24 [2] 43 06 [2] 57 1d [2] 58 07 [2] 46 1a [2] 44 1b [2] 5f 1d [2] 43 1a [2] 5f 35 }

  condition:
    any of them
}