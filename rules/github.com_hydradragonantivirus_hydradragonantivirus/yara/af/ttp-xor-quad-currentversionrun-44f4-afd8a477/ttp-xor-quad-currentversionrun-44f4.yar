rule TTP_XOR_QUAD_CurrentVersionRun_44f4 {
  strings:
    $key_44f4 = { 17 9b [2] 33 95 [2] 18 b9 [2] 36 9b [2] 22 80 [2] 2d 9a [2] 33 87 [2] 31 86 [2] 2a 80 [2] 36 87 [2] 2a a8 }

  condition:
    any of them
}