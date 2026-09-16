rule TTP_XOR_QUAD_CurrentVersionRun_6893 {
  strings:
    $key_6893 = { 3b fc [2] 1f f2 [2] 34 de [2] 1a fc [2] 0e e7 [2] 01 fd [2] 1f e0 [2] 1d e1 [2] 06 e7 [2] 1a e0 [2] 06 cf }

  condition:
    any of them
}