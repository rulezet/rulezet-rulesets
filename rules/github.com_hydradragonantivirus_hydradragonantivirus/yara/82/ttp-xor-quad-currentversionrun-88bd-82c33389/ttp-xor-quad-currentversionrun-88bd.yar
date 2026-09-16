rule TTP_XOR_QUAD_CurrentVersionRun_88bd {
  strings:
    $key_88bd = { db d2 [2] ff dc [2] d4 f0 [2] fa d2 [2] ee c9 [2] e1 d3 [2] ff ce [2] fd cf [2] e6 c9 [2] fa ce [2] e6 e1 }

  condition:
    any of them
}