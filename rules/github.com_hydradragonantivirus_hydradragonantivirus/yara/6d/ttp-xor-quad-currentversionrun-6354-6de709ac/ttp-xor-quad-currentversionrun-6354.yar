rule TTP_XOR_QUAD_CurrentVersionRun_6354 {
  strings:
    $key_6354 = { 30 3b [2] 14 35 [2] 3f 19 [2] 11 3b [2] 05 20 [2] 0a 3a [2] 14 27 [2] 16 26 [2] 0d 20 [2] 11 27 [2] 0d 08 }

  condition:
    any of them
}