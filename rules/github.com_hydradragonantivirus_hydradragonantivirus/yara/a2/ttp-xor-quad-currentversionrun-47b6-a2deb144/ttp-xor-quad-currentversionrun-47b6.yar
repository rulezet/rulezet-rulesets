rule TTP_XOR_QUAD_CurrentVersionRun_47b6 {
  strings:
    $key_47b6 = { 14 d9 [2] 30 d7 [2] 1b fb [2] 35 d9 [2] 21 c2 [2] 2e d8 [2] 30 c5 [2] 32 c4 [2] 29 c2 [2] 35 c5 [2] 29 ea }

  condition:
    any of them
}