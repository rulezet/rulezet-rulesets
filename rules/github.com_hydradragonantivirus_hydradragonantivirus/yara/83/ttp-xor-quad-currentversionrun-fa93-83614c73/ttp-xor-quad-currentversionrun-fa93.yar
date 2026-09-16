rule TTP_XOR_QUAD_CurrentVersionRun_fa93 {
  strings:
    $key_fa93 = { a9 fc [2] 8d f2 [2] a6 de [2] 88 fc [2] 9c e7 [2] 93 fd [2] 8d e0 [2] 8f e1 [2] 94 e7 [2] 88 e0 [2] 94 cf }

  condition:
    any of them
}