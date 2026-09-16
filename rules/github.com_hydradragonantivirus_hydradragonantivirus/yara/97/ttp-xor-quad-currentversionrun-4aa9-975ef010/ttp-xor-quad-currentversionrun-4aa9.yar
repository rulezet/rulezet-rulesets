rule TTP_XOR_QUAD_CurrentVersionRun_4aa9 {
  strings:
    $key_4aa9 = { 19 c6 [2] 3d c8 [2] 16 e4 [2] 38 c6 [2] 2c dd [2] 23 c7 [2] 3d da [2] 3f db [2] 24 dd [2] 38 da [2] 24 f5 }

  condition:
    any of them
}