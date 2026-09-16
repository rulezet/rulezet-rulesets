rule TTP_XOR_QUAD_CurrentVersionRun_4af8 {
  strings:
    $key_4af8 = { 19 97 [2] 3d 99 [2] 16 b5 [2] 38 97 [2] 2c 8c [2] 23 96 [2] 3d 8b [2] 3f 8a [2] 24 8c [2] 38 8b [2] 24 a4 }

  condition:
    any of them
}