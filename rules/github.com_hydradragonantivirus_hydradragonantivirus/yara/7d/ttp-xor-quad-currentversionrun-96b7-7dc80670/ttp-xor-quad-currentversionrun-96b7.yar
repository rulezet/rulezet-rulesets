rule TTP_XOR_QUAD_CurrentVersionRun_96b7 {
  strings:
    $key_96b7 = { c5 d8 [2] e1 d6 [2] ca fa [2] e4 d8 [2] f0 c3 [2] ff d9 [2] e1 c4 [2] e3 c5 [2] f8 c3 [2] e4 c4 [2] f8 eb }

  condition:
    any of them
}