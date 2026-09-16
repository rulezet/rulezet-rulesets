rule TTP_XOR_QUAD_CurrentVersionRun_44e4 {
  strings:
    $key_44e4 = { 17 8b [2] 33 85 [2] 18 a9 [2] 36 8b [2] 22 90 [2] 2d 8a [2] 33 97 [2] 31 96 [2] 2a 90 [2] 36 97 [2] 2a b8 }

  condition:
    any of them
}