rule TTP_XOR_QUAD_CurrentVersionRun_2a93 {
  strings:
    $key_2a93 = { 79 fc [2] 5d f2 [2] 76 de [2] 58 fc [2] 4c e7 [2] 43 fd [2] 5d e0 [2] 5f e1 [2] 44 e7 [2] 58 e0 [2] 44 cf }

  condition:
    any of them
}