rule TTP_XOR_QUAD_CurrentVersionRun_47a6 {
  strings:
    $key_47a6 = { 14 c9 [2] 30 c7 [2] 1b eb [2] 35 c9 [2] 21 d2 [2] 2e c8 [2] 30 d5 [2] 32 d4 [2] 29 d2 [2] 35 d5 [2] 29 fa }

  condition:
    any of them
}