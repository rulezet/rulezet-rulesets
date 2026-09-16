rule TTP_XOR_QUAD_CurrentVersionRun_96e6 {
  strings:
    $key_96e6 = { c5 89 [2] e1 87 [2] ca ab [2] e4 89 [2] f0 92 [2] ff 88 [2] e1 95 [2] e3 94 [2] f8 92 [2] e4 95 [2] f8 ba }

  condition:
    any of them
}