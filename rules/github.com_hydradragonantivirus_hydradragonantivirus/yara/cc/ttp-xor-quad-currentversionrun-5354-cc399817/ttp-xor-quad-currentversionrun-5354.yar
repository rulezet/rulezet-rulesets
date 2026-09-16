rule TTP_XOR_QUAD_CurrentVersionRun_5354 {
  strings:
    $key_5354 = { 00 3b [2] 24 35 [2] 0f 19 [2] 21 3b [2] 35 20 [2] 3a 3a [2] 24 27 [2] 26 26 [2] 3d 20 [2] 21 27 [2] 3d 08 }

  condition:
    any of them
}