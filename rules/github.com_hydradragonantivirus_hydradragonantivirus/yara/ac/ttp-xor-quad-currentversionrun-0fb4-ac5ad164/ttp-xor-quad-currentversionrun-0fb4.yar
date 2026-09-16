rule TTP_XOR_QUAD_CurrentVersionRun_0fb4 {
  strings:
    $key_0fb4 = { 5c db [2] 78 d5 [2] 53 f9 [2] 7d db [2] 69 c0 [2] 66 da [2] 78 c7 [2] 7a c6 [2] 61 c0 [2] 7d c7 [2] 61 e8 }

  condition:
    any of them
}