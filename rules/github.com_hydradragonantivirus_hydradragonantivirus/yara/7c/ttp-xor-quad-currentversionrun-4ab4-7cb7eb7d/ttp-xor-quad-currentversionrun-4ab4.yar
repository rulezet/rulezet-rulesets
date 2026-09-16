rule TTP_XOR_QUAD_CurrentVersionRun_4ab4 {
  strings:
    $key_4ab4 = { 19 db [2] 3d d5 [2] 16 f9 [2] 38 db [2] 2c c0 [2] 23 da [2] 3d c7 [2] 3f c6 [2] 24 c0 [2] 38 c7 [2] 24 e8 }

  condition:
    any of them
}