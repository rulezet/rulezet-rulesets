rule TTP_XOR_QUAD_CurrentVersionRun_53e5 {
  strings:
    $key_53e5 = { 00 8a [2] 24 84 [2] 0f a8 [2] 21 8a [2] 35 91 [2] 3a 8b [2] 24 96 [2] 26 97 [2] 3d 91 [2] 21 96 [2] 3d b9 }

  condition:
    any of them
}