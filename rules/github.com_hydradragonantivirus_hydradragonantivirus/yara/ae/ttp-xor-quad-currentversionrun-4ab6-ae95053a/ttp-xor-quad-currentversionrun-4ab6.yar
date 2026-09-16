rule TTP_XOR_QUAD_CurrentVersionRun_4ab6 {
  strings:
    $key_4ab6 = { 19 d9 [2] 3d d7 [2] 16 fb [2] 38 d9 [2] 2c c2 [2] 23 d8 [2] 3d c5 [2] 3f c4 [2] 24 c2 [2] 38 c5 [2] 24 ea }

  condition:
    any of them
}