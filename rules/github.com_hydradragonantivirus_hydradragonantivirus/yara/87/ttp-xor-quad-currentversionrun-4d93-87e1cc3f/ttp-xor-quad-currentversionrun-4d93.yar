rule TTP_XOR_QUAD_CurrentVersionRun_4d93 {
  strings:
    $key_4d93 = { 1e fc [2] 3a f2 [2] 11 de [2] 3f fc [2] 2b e7 [2] 24 fd [2] 3a e0 [2] 38 e1 [2] 23 e7 [2] 3f e0 [2] 23 cf }

  condition:
    any of them
}