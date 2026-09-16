rule TTP_XOR_QUAD_CurrentVersionRun_3155 {
  strings:
    $key_3155 = { 62 3a [2] 46 34 [2] 6d 18 [2] 43 3a [2] 57 21 [2] 58 3b [2] 46 26 [2] 44 27 [2] 5f 21 [2] 43 26 [2] 5f 09 }

  condition:
    any of them
}