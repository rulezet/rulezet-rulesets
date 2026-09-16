rule TTP_XOR_QUAD_CurrentVersionRun_8a8b {
  strings:
    $key_8a8b = { d9 e4 [2] fd ea [2] d6 c6 [2] f8 e4 [2] ec ff [2] e3 e5 [2] fd f8 [2] ff f9 [2] e4 ff [2] f8 f8 [2] e4 d7 }

  condition:
    any of them
}