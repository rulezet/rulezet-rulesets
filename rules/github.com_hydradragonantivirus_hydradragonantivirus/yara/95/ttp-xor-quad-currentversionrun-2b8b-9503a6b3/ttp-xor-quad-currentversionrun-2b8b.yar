rule TTP_XOR_QUAD_CurrentVersionRun_2b8b {
  strings:
    $key_2b8b = { 78 e4 [2] 5c ea [2] 77 c6 [2] 59 e4 [2] 4d ff [2] 42 e5 [2] 5c f8 [2] 5e f9 [2] 45 ff [2] 59 f8 [2] 45 d7 }

  condition:
    any of them
}