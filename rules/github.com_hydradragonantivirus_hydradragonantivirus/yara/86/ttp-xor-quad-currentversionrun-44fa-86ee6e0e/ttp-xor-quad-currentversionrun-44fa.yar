rule TTP_XOR_QUAD_CurrentVersionRun_44fa {
  strings:
    $key_44fa = { 17 95 [2] 33 9b [2] 18 b7 [2] 36 95 [2] 22 8e [2] 2d 94 [2] 33 89 [2] 31 88 [2] 2a 8e [2] 36 89 [2] 2a a6 }

  condition:
    any of them
}