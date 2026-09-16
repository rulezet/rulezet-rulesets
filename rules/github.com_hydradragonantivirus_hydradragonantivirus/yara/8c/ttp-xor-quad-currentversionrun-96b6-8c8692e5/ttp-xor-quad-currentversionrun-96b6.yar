rule TTP_XOR_QUAD_CurrentVersionRun_96b6 {
  strings:
    $key_96b6 = { c5 d9 [2] e1 d7 [2] ca fb [2] e4 d9 [2] f0 c2 [2] ff d8 [2] e1 c5 [2] e3 c4 [2] f8 c2 [2] e4 c5 [2] f8 ea }

  condition:
    any of them
}