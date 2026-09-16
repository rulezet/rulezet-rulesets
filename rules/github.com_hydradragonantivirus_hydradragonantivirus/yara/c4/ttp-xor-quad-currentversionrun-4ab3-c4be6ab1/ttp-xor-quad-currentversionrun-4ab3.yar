rule TTP_XOR_QUAD_CurrentVersionRun_4ab3 {
  strings:
    $key_4ab3 = { 19 dc [2] 3d d2 [2] 16 fe [2] 38 dc [2] 2c c7 [2] 23 dd [2] 3d c0 [2] 3f c1 [2] 24 c7 [2] 38 c0 [2] 24 ef }

  condition:
    any of them
}