rule TTP_XOR_QUAD_CurrentVersionRun_4f14 {
  strings:
    $key_4f14 = { 1c 7b [2] 38 75 [2] 13 59 [2] 3d 7b [2] 29 60 [2] 26 7a [2] 38 67 [2] 3a 66 [2] 21 60 [2] 3d 67 [2] 21 48 }

  condition:
    any of them
}