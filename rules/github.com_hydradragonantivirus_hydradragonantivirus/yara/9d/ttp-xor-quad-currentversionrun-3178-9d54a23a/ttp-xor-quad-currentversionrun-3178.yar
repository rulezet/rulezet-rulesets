rule TTP_XOR_QUAD_CurrentVersionRun_3178 {
  strings:
    $key_3178 = { 62 17 [2] 46 19 [2] 6d 35 [2] 43 17 [2] 57 0c [2] 58 16 [2] 46 0b [2] 44 0a [2] 5f 0c [2] 43 0b [2] 5f 24 }

  condition:
    any of them
}