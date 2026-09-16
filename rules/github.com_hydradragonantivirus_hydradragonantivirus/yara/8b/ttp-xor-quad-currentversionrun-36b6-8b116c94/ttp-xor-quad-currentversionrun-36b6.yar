rule TTP_XOR_QUAD_CurrentVersionRun_36b6 {
  strings:
    $key_36b6 = { 65 d9 [2] 41 d7 [2] 6a fb [2] 44 d9 [2] 50 c2 [2] 5f d8 [2] 41 c5 [2] 43 c4 [2] 58 c2 [2] 44 c5 [2] 58 ea }

  condition:
    any of them
}