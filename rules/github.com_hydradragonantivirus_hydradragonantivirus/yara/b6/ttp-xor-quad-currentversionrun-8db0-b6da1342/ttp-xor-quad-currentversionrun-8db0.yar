rule TTP_XOR_QUAD_CurrentVersionRun_8db0 {
  strings:
    $key_8db0 = { de df [2] fa d1 [2] d1 fd [2] ff df [2] eb c4 [2] e4 de [2] fa c3 [2] f8 c2 [2] e3 c4 [2] ff c3 [2] e3 ec }

  condition:
    any of them
}