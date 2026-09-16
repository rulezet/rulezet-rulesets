rule TTP_XOR_QUAD_CurrentVersionRun_889d {
  strings:
    $key_889d = { db f2 [2] ff fc [2] d4 d0 [2] fa f2 [2] ee e9 [2] e1 f3 [2] ff ee [2] fd ef [2] e6 e9 [2] fa ee [2] e6 c1 }

  condition:
    any of them
}