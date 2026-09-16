rule TTP_XOR_QUAD_CurrentVersionRun_2497 {
  strings:
    $key_2497 = { 77 f8 [2] 53 f6 [2] 78 da [2] 56 f8 [2] 42 e3 [2] 4d f9 [2] 53 e4 [2] 51 e5 [2] 4a e3 [2] 56 e4 [2] 4a cb }

  condition:
    any of them
}