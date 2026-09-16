rule TTP_XOR_QUAD_CurrentVersionRun_3164 {
  strings:
    $key_3164 = { 62 0b [2] 46 05 [2] 6d 29 [2] 43 0b [2] 57 10 [2] 58 0a [2] 46 17 [2] 44 16 [2] 5f 10 [2] 43 17 [2] 5f 38 }

  condition:
    any of them
}