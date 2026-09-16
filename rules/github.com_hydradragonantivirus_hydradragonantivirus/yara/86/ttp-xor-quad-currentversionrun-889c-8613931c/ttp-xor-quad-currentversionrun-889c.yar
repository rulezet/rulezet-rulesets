rule TTP_XOR_QUAD_CurrentVersionRun_889c {
  strings:
    $key_889c = { db f3 [2] ff fd [2] d4 d1 [2] fa f3 [2] ee e8 [2] e1 f2 [2] ff ef [2] fd ee [2] e6 e8 [2] fa ef [2] e6 c0 }

  condition:
    any of them
}