rule TTP_XOR_QUAD_CurrentVersionRun_56b4 {
  strings:
    $key_56b4 = { 05 db [2] 21 d5 [2] 0a f9 [2] 24 db [2] 30 c0 [2] 3f da [2] 21 c7 [2] 23 c6 [2] 38 c0 [2] 24 c7 [2] 38 e8 }

  condition:
    any of them
}