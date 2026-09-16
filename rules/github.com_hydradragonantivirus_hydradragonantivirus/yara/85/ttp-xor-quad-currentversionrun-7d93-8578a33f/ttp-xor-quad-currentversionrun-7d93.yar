rule TTP_XOR_QUAD_CurrentVersionRun_7d93 {
  strings:
    $key_7d93 = { 2e fc [2] 0a f2 [2] 21 de [2] 0f fc [2] 1b e7 [2] 14 fd [2] 0a e0 [2] 08 e1 [2] 13 e7 [2] 0f e0 [2] 13 cf }

  condition:
    any of them
}