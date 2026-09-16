rule TTP_XOR_QUAD_CurrentVersionRun_4e93 {
  strings:
    $key_4e93 = { 1d fc [2] 39 f2 [2] 12 de [2] 3c fc [2] 28 e7 [2] 27 fd [2] 39 e0 [2] 3b e1 [2] 20 e7 [2] 3c e0 [2] 20 cf }

  condition:
    any of them
}