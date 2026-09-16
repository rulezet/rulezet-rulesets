rule TTP_XOR_QUAD_CurrentVersionRun_2fb4 {
  strings:
    $key_2fb4 = { 7c db [2] 58 d5 [2] 73 f9 [2] 5d db [2] 49 c0 [2] 46 da [2] 58 c7 [2] 5a c6 [2] 41 c0 [2] 5d c7 [2] 41 e8 }

  condition:
    any of them
}