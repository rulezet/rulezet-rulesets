rule TTP_XOR_QUAD_CurrentVersionRun_8d93 {
  strings:
    $key_8d93 = { de fc [2] fa f2 [2] d1 de [2] ff fc [2] eb e7 [2] e4 fd [2] fa e0 [2] f8 e1 [2] e3 e7 [2] ff e0 [2] e3 cf }

  condition:
    any of them
}