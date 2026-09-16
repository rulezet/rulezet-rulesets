rule TTP_XOR_QUAD_CurrentVersionRun_1e93 {
  strings:
    $key_1e93 = { 4d fc [2] 69 f2 [2] 42 de [2] 6c fc [2] 78 e7 [2] 77 fd [2] 69 e0 [2] 6b e1 [2] 70 e7 [2] 6c e0 [2] 70 cf }

  condition:
    any of them
}