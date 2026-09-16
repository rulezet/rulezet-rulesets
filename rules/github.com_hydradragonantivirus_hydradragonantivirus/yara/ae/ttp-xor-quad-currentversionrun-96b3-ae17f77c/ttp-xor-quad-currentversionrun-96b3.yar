rule TTP_XOR_QUAD_CurrentVersionRun_96b3 {
  strings:
    $key_96b3 = { c5 dc [2] e1 d2 [2] ca fe [2] e4 dc [2] f0 c7 [2] ff dd [2] e1 c0 [2] e3 c1 [2] f8 c7 [2] e4 c0 [2] f8 ef }

  condition:
    any of them
}