rule TTP_XOR_QUAD_CurrentVersionRun_53e8 {
  strings:
    $key_53e8 = { 00 87 [2] 24 89 [2] 0f a5 [2] 21 87 [2] 35 9c [2] 3a 86 [2] 24 9b [2] 26 9a [2] 3d 9c [2] 21 9b [2] 3d b4 }

  condition:
    any of them
}