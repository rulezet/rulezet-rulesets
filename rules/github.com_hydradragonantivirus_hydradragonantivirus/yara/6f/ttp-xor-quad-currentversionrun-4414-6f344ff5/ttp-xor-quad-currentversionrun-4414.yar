rule TTP_XOR_QUAD_CurrentVersionRun_4414 {
  strings:
    $key_4414 = { 17 7b [2] 33 75 [2] 18 59 [2] 36 7b [2] 22 60 [2] 2d 7a [2] 33 67 [2] 31 66 [2] 2a 60 [2] 36 67 [2] 2a 48 }

  condition:
    any of them
}