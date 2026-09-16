rule TTP_XOR_QUAD_CurrentVersionRun_2b97 {
  strings:
    $key_2b97 = { 78 f8 [2] 5c f6 [2] 77 da [2] 59 f8 [2] 4d e3 [2] 42 f9 [2] 5c e4 [2] 5e e5 [2] 45 e3 [2] 59 e4 [2] 45 cb }

  condition:
    any of them
}