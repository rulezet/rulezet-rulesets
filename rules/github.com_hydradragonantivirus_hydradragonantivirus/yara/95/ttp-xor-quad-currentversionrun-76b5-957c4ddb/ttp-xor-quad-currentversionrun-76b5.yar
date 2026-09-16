rule TTP_XOR_QUAD_CurrentVersionRun_76b5 {
  strings:
    $key_76b5 = { 25 da [2] 01 d4 [2] 2a f8 [2] 04 da [2] 10 c1 [2] 1f db [2] 01 c6 [2] 03 c7 [2] 18 c1 [2] 04 c6 [2] 18 e9 }

  condition:
    any of them
}