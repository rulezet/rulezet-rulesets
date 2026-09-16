rule TTP_XOR_QUAD_CurrentVersionRun_5bb3 {
  strings:
    $key_5bb3 = { 08 dc [2] 2c d2 [2] 07 fe [2] 29 dc [2] 3d c7 [2] 32 dd [2] 2c c0 [2] 2e c1 [2] 35 c7 [2] 29 c0 [2] 35 ef }

  condition:
    any of them
}