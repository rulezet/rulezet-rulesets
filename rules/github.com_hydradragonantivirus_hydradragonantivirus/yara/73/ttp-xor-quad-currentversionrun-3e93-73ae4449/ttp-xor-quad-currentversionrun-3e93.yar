rule TTP_XOR_QUAD_CurrentVersionRun_3e93 {
  strings:
    $key_3e93 = { 6d fc [2] 49 f2 [2] 62 de [2] 4c fc [2] 58 e7 [2] 57 fd [2] 49 e0 [2] 4b e1 [2] 50 e7 [2] 4c e0 [2] 50 cf }

  condition:
    any of them
}