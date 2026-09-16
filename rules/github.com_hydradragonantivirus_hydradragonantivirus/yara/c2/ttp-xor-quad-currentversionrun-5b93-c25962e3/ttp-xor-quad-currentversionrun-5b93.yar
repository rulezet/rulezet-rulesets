rule TTP_XOR_QUAD_CurrentVersionRun_5b93 {
  strings:
    $key_5b93 = { 08 fc [2] 2c f2 [2] 07 de [2] 29 fc [2] 3d e7 [2] 32 fd [2] 2c e0 [2] 2e e1 [2] 35 e7 [2] 29 e0 [2] 35 cf }

  condition:
    any of them
}