rule TTP_XOR_QUAD_CurrentVersionRun_36b4 {
  strings:
    $key_36b4 = { 65 db [2] 41 d5 [2] 6a f9 [2] 44 db [2] 50 c0 [2] 5f da [2] 41 c7 [2] 43 c6 [2] 58 c0 [2] 44 c7 [2] 58 e8 }

  condition:
    any of them
}