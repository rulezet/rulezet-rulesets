rule TTP_XOR_QUAD_CurrentVersionRun_96fa {
  strings:
    $key_96fa = { c5 95 [2] e1 9b [2] ca b7 [2] e4 95 [2] f0 8e [2] ff 94 [2] e1 89 [2] e3 88 [2] f8 8e [2] e4 89 [2] f8 a6 }

  condition:
    any of them
}