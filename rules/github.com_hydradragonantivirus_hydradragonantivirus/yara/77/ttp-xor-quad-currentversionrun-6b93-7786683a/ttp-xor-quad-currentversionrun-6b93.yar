rule TTP_XOR_QUAD_CurrentVersionRun_6b93 {
  strings:
    $key_6b93 = { 38 fc [2] 1c f2 [2] 37 de [2] 19 fc [2] 0d e7 [2] 02 fd [2] 1c e0 [2] 1e e1 [2] 05 e7 [2] 19 e0 [2] 05 cf }

  condition:
    any of them
}