rule TTP_XOR_QUAD_CurrentVersionRun_96f4 {
  strings:
    $key_96f4 = { c5 9b [2] e1 95 [2] ca b9 [2] e4 9b [2] f0 80 [2] ff 9a [2] e1 87 [2] e3 86 [2] f8 80 [2] e4 87 [2] f8 a8 }

  condition:
    any of them
}