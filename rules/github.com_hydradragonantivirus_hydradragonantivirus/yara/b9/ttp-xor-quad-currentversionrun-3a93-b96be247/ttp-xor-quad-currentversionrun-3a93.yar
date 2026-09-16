rule TTP_XOR_QUAD_CurrentVersionRun_3a93 {
  strings:
    $key_3a93 = { 69 fc [2] 4d f2 [2] 66 de [2] 48 fc [2] 5c e7 [2] 53 fd [2] 4d e0 [2] 4f e1 [2] 54 e7 [2] 48 e0 [2] 54 cf }

  condition:
    any of them
}