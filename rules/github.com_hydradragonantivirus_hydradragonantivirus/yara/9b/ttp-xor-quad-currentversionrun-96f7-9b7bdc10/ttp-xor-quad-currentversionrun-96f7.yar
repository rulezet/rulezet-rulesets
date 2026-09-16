rule TTP_XOR_QUAD_CurrentVersionRun_96f7 {
  strings:
    $key_96f7 = { c5 98 [2] e1 96 [2] ca ba [2] e4 98 [2] f0 83 [2] ff 99 [2] e1 84 [2] e3 85 [2] f8 83 [2] e4 84 [2] f8 ab }

  condition:
    any of them
}