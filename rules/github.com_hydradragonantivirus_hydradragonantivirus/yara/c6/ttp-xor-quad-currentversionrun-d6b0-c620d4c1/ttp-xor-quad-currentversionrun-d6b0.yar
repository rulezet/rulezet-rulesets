rule TTP_XOR_QUAD_CurrentVersionRun_d6b0 {
  strings:
    $key_d6b0 = { 85 df [2] a1 d1 [2] 8a fd [2] a4 df [2] b0 c4 [2] bf de [2] a1 c3 [2] a3 c2 [2] b8 c4 [2] a4 c3 [2] b8 ec }

  condition:
    any of them
}