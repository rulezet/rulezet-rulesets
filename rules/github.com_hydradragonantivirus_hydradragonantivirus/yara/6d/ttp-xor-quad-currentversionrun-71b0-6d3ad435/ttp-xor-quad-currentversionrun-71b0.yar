rule TTP_XOR_QUAD_CurrentVersionRun_71b0 {
  strings:
    $key_71b0 = { 22 df [2] 06 d1 [2] 2d fd [2] 03 df [2] 17 c4 [2] 18 de [2] 06 c3 [2] 04 c2 [2] 1f c4 [2] 03 c3 [2] 1f ec }

  condition:
    any of them
}