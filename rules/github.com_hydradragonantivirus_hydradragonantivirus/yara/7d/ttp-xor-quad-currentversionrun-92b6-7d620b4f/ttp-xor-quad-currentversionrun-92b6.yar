rule TTP_XOR_QUAD_CurrentVersionRun_92b6 {
  strings:
    $key_92b6 = { c1 d9 [2] e5 d7 [2] ce fb [2] e0 d9 [2] f4 c2 [2] fb d8 [2] e5 c5 [2] e7 c4 [2] fc c2 [2] e0 c5 [2] fc ea }

  condition:
    any of them
}