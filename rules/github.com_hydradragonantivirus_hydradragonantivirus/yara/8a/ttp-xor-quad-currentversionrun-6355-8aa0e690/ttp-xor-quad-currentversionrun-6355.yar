rule TTP_XOR_QUAD_CurrentVersionRun_6355 {
  strings:
    $key_6355 = { 30 3a [2] 14 34 [2] 3f 18 [2] 11 3a [2] 05 21 [2] 0a 3b [2] 14 26 [2] 16 27 [2] 0d 21 [2] 11 26 [2] 0d 09 }

  condition:
    any of them
}