rule TTP_XOR_QUAD_CurrentVersionRun_87b6 {
  strings:
    $key_87b6 = { d4 d9 [2] f0 d7 [2] db fb [2] f5 d9 [2] e1 c2 [2] ee d8 [2] f0 c5 [2] f2 c4 [2] e9 c2 [2] f5 c5 [2] e9 ea }

  condition:
    any of them
}