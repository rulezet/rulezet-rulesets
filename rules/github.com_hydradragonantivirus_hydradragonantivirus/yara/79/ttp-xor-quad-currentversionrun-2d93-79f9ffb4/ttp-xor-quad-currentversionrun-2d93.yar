rule TTP_XOR_QUAD_CurrentVersionRun_2d93 {
  strings:
    $key_2d93 = { 7e fc [2] 5a f2 [2] 71 de [2] 5f fc [2] 4b e7 [2] 44 fd [2] 5a e0 [2] 58 e1 [2] 43 e7 [2] 5f e0 [2] 43 cf }

  condition:
    any of them
}