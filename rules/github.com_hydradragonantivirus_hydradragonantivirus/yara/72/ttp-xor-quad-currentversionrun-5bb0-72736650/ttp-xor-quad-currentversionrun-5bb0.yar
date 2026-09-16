rule TTP_XOR_QUAD_CurrentVersionRun_5bb0 {
  strings:
    $key_5bb0 = { 08 df [2] 2c d1 [2] 07 fd [2] 29 df [2] 3d c4 [2] 32 de [2] 2c c3 [2] 2e c2 [2] 35 c4 [2] 29 c3 [2] 35 ec }

  condition:
    any of them
}