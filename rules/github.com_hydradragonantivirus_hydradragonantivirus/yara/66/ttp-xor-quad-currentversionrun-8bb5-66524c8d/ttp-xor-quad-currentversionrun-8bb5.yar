rule TTP_XOR_QUAD_CurrentVersionRun_8bb5 {
  strings:
    $key_8bb5 = { d8 da [2] fc d4 [2] d7 f8 [2] f9 da [2] ed c1 [2] e2 db [2] fc c6 [2] fe c7 [2] e5 c1 [2] f9 c6 [2] e5 e9 }

  condition:
    any of them
}