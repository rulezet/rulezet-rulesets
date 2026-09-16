rule TTP_XOR_QUAD_CurrentVersionRun_90b0 {
  strings:
    $key_90b0 = { c3 df [2] e7 d1 [2] cc fd [2] e2 df [2] f6 c4 [2] f9 de [2] e7 c3 [2] e5 c2 [2] fe c4 [2] e2 c3 [2] fe ec }

  condition:
    any of them
}