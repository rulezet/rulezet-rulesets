rule TTP_XOR_QUAD_CurrentVersionRun_61b0 {
  strings:
    $key_61b0 = { 32 df [2] 16 d1 [2] 3d fd [2] 13 df [2] 07 c4 [2] 08 de [2] 16 c3 [2] 14 c2 [2] 0f c4 [2] 13 c3 [2] 0f ec }

  condition:
    any of them
}