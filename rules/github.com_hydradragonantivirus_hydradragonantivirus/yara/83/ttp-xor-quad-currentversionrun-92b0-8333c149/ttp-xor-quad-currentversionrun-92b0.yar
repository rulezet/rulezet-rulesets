rule TTP_XOR_QUAD_CurrentVersionRun_92b0 {
  strings:
    $key_92b0 = { c1 df [2] e5 d1 [2] ce fd [2] e0 df [2] f4 c4 [2] fb de [2] e5 c3 [2] e7 c2 [2] fc c4 [2] e0 c3 [2] fc ec }

  condition:
    any of them
}