rule TTP_XOR_QUAD_CurrentVersionRun_8bb4 {
  strings:
    $key_8bb4 = { d8 db [2] fc d5 [2] d7 f9 [2] f9 db [2] ed c0 [2] e2 da [2] fc c7 [2] fe c6 [2] e5 c0 [2] f9 c7 [2] e5 e8 }

  condition:
    any of them
}