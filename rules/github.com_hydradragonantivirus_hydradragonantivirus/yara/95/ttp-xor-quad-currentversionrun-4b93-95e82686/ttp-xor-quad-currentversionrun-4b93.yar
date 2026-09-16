rule TTP_XOR_QUAD_CurrentVersionRun_4b93 {
  strings:
    $key_4b93 = { 18 fc [2] 3c f2 [2] 17 de [2] 39 fc [2] 2d e7 [2] 22 fd [2] 3c e0 [2] 3e e1 [2] 25 e7 [2] 39 e0 [2] 25 cf }

  condition:
    any of them
}