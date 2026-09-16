rule TTP_XOR_QUAD_CurrentVersionRun_8893 {
  strings:
    $key_8893 = { db fc [2] ff f2 [2] d4 de [2] fa fc [2] ee e7 [2] e1 fd [2] ff e0 [2] fd e1 [2] e6 e7 [2] fa e0 [2] e6 cf }

  condition:
    any of them
}