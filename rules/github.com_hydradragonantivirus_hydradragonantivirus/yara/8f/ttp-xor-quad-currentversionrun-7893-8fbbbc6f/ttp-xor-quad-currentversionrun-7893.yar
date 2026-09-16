rule TTP_XOR_QUAD_CurrentVersionRun_7893 {
  strings:
    $key_7893 = { 2b fc [2] 0f f2 [2] 24 de [2] 0a fc [2] 1e e7 [2] 11 fd [2] 0f e0 [2] 0d e1 [2] 16 e7 [2] 0a e0 [2] 16 cf }

  condition:
    any of them
}