rule TTP_XOR_QUAD_CurrentVersionRun_7993 {
  strings:
    $key_7993 = { 2a fc [2] 0e f2 [2] 25 de [2] 0b fc [2] 1f e7 [2] 10 fd [2] 0e e0 [2] 0c e1 [2] 17 e7 [2] 0b e0 [2] 17 cf }

  condition:
    any of them
}