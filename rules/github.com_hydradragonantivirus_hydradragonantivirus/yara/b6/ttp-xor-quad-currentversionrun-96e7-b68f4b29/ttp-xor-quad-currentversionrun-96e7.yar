rule TTP_XOR_QUAD_CurrentVersionRun_96e7 {
  strings:
    $key_96e7 = { c5 88 [2] e1 86 [2] ca aa [2] e4 88 [2] f0 93 [2] ff 89 [2] e1 94 [2] e3 95 [2] f8 93 [2] e4 94 [2] f8 bb }

  condition:
    any of them
}