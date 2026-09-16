rule TTP_XOR_QUAD_CurrentVersionRun_88b0 {
  strings:
    $key_88b0 = { db df [2] ff d1 [2] d4 fd [2] fa df [2] ee c4 [2] e1 de [2] ff c3 [2] fd c2 [2] e6 c4 [2] fa c3 [2] e6 ec }

  condition:
    any of them
}