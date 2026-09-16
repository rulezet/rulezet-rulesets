rule TTP_XOR_QUAD_CurrentVersionRun_acb0 {
  strings:
    $key_acb0 = { ff df [2] db d1 [2] f0 fd [2] de df [2] ca c4 [2] c5 de [2] db c3 [2] d9 c2 [2] c2 c4 [2] de c3 [2] c2 ec }

  condition:
    any of them
}