rule TTP_XOR_QUAD_CurrentVersionRun_5a93 {
  strings:
    $key_5a93 = { 09 fc [2] 2d f2 [2] 06 de [2] 28 fc [2] 3c e7 [2] 33 fd [2] 2d e0 [2] 2f e1 [2] 34 e7 [2] 28 e0 [2] 34 cf }

  condition:
    any of them
}