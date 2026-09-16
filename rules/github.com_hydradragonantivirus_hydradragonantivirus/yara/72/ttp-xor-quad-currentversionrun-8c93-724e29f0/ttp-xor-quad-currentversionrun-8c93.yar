rule TTP_XOR_QUAD_CurrentVersionRun_8c93 {
  strings:
    $key_8c93 = { df fc [2] fb f2 [2] d0 de [2] fe fc [2] ea e7 [2] e5 fd [2] fb e0 [2] f9 e1 [2] e2 e7 [2] fe e0 [2] e2 cf }

  condition:
    any of them
}