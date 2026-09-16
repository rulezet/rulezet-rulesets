rule TTP_XOR_QUAD_CurrentVersionRun_8bb7 {
  strings:
    $key_8bb7 = { d8 d8 [2] fc d6 [2] d7 fa [2] f9 d8 [2] ed c3 [2] e2 d9 [2] fc c4 [2] fe c5 [2] e5 c3 [2] f9 c4 [2] e5 eb }

  condition:
    any of them
}