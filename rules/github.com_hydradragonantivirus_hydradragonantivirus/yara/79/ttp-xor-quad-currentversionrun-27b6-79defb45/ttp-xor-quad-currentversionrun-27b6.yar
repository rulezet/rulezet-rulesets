rule TTP_XOR_QUAD_CurrentVersionRun_27b6 {
  strings:
    $key_27b6 = { 74 d9 [2] 50 d7 [2] 7b fb [2] 55 d9 [2] 41 c2 [2] 4e d8 [2] 50 c5 [2] 52 c4 [2] 49 c2 [2] 55 c5 [2] 49 ea }

  condition:
    any of them
}