rule TTP_XOR_QUAD_CurrentVersionRun_4af5 {
  strings:
    $key_4af5 = { 19 9a [2] 3d 94 [2] 16 b8 [2] 38 9a [2] 2c 81 [2] 23 9b [2] 3d 86 [2] 3f 87 [2] 24 81 [2] 38 86 [2] 24 a9 }

  condition:
    any of them
}