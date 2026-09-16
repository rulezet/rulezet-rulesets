rule TTP_XOR_QUAD_CurrentVersionRun_46b5 {
  strings:
    $key_46b5 = { 15 da [2] 31 d4 [2] 1a f8 [2] 34 da [2] 20 c1 [2] 2f db [2] 31 c6 [2] 33 c7 [2] 28 c1 [2] 34 c6 [2] 28 e9 }

  condition:
    any of them
}