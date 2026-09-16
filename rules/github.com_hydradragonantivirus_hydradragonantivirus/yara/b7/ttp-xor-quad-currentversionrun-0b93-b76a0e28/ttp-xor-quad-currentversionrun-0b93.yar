rule TTP_XOR_QUAD_CurrentVersionRun_0b93 {
  strings:
    $key_0b93 = { 58 fc [2] 7c f2 [2] 57 de [2] 79 fc [2] 6d e7 [2] 62 fd [2] 7c e0 [2] 7e e1 [2] 65 e7 [2] 79 e0 [2] 65 cf }

  condition:
    any of them
}