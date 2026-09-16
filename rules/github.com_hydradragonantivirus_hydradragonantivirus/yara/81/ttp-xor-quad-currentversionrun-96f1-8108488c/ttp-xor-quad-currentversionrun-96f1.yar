rule TTP_XOR_QUAD_CurrentVersionRun_96f1 {
  strings:
    $key_96f1 = { c5 9e [2] e1 90 [2] ca bc [2] e4 9e [2] f0 85 [2] ff 9f [2] e1 82 [2] e3 83 [2] f8 85 [2] e4 82 [2] f8 ad }

  condition:
    any of them
}