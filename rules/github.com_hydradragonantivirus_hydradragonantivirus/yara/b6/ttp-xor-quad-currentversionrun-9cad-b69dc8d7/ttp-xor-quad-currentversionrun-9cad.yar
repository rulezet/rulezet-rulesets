rule TTP_XOR_QUAD_CurrentVersionRun_9cad {
  strings:
    $key_9cad = { cf c2 [2] eb cc [2] c0 e0 [2] ee c2 [2] fa d9 [2] f5 c3 [2] eb de [2] e9 df [2] f2 d9 [2] ee de [2] f2 f1 }

  condition:
    any of them
}