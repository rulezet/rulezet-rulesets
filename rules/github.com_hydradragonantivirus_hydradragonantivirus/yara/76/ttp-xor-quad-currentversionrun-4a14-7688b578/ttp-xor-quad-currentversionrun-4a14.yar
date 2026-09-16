rule TTP_XOR_QUAD_CurrentVersionRun_4a14 {
  strings:
    $key_4a14 = { 19 7b [2] 3d 75 [2] 16 59 [2] 38 7b [2] 2c 60 [2] 23 7a [2] 3d 67 [2] 3f 66 [2] 24 60 [2] 38 67 [2] 24 48 }

  condition:
    any of them
}