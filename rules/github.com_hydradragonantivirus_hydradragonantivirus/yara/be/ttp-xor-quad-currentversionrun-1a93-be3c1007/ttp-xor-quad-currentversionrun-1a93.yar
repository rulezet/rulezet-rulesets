rule TTP_XOR_QUAD_CurrentVersionRun_1a93 {
  strings:
    $key_1a93 = { 49 fc [2] 6d f2 [2] 46 de [2] 68 fc [2] 7c e7 [2] 73 fd [2] 6d e0 [2] 6f e1 [2] 74 e7 [2] 68 e0 [2] 74 cf }

  condition:
    any of them
}