rule TTP_XOR_QUAD_CurrentVersionRun_a5b0 {
  strings:
    $key_a5b0 = { f6 df [2] d2 d1 [2] f9 fd [2] d7 df [2] c3 c4 [2] cc de [2] d2 c3 [2] d0 c2 [2] cb c4 [2] d7 c3 [2] cb ec }

  condition:
    any of them
}