rule TTP_XOR_QUAD_CurrentVersionRun_07b6 {
  strings:
    $key_07b6 = { 54 d9 [2] 70 d7 [2] 5b fb [2] 75 d9 [2] 61 c2 [2] 6e d8 [2] 70 c5 [2] 72 c4 [2] 69 c2 [2] 75 c5 [2] 69 ea }

  condition:
    any of them
}