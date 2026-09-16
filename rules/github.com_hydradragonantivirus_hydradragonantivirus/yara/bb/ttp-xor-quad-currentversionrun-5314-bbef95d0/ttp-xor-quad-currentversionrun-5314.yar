rule TTP_XOR_QUAD_CurrentVersionRun_5314 {
  strings:
    $key_5314 = { 00 7b [2] 24 75 [2] 0f 59 [2] 21 7b [2] 35 60 [2] 3a 7a [2] 24 67 [2] 26 66 [2] 3d 60 [2] 21 67 [2] 3d 48 }

  condition:
    any of them
}