rule TTP_XOR_QUAD_CurrentVersionRun_8b93 {
  strings:
    $key_8b93 = { d8 fc [2] fc f2 [2] d7 de [2] f9 fc [2] ed e7 [2] e2 fd [2] fc e0 [2] fe e1 [2] e5 e7 [2] f9 e0 [2] e5 cf }

  condition:
    any of them
}