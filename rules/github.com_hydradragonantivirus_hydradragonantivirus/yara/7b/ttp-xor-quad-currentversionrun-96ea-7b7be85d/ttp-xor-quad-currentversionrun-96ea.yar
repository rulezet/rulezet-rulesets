rule TTP_XOR_QUAD_CurrentVersionRun_96ea {
  strings:
    $key_96ea = { c5 85 [2] e1 8b [2] ca a7 [2] e4 85 [2] f0 9e [2] ff 84 [2] e1 99 [2] e3 98 [2] f8 9e [2] e4 99 [2] f8 b6 }

  condition:
    any of them
}