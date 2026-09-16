rule TTP_XOR_QUAD_CurrentVersionRun_2b93 {
  strings:
    $key_2b93 = { 78 fc [2] 5c f2 [2] 77 de [2] 59 fc [2] 4d e7 [2] 42 fd [2] 5c e0 [2] 5e e1 [2] 45 e7 [2] 59 e0 [2] 45 cf }

  condition:
    any of them
}