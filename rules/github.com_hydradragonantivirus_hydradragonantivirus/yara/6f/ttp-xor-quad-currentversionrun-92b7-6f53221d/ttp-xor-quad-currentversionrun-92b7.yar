rule TTP_XOR_QUAD_CurrentVersionRun_92b7 {
  strings:
    $key_92b7 = { c1 d8 [2] e5 d6 [2] ce fa [2] e0 d8 [2] f4 c3 [2] fb d9 [2] e5 c4 [2] e7 c5 [2] fc c3 [2] e0 c4 [2] fc eb }

  condition:
    any of them
}