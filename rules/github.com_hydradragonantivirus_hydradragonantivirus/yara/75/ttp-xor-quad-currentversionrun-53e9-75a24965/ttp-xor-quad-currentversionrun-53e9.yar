rule TTP_XOR_QUAD_CurrentVersionRun_53e9 {
  strings:
    $key_53e9 = { 00 86 [2] 24 88 [2] 0f a4 [2] 21 86 [2] 35 9d [2] 3a 87 [2] 24 9a [2] 26 9b [2] 3d 9d [2] 21 9a [2] 3d b5 }

  condition:
    any of them
}