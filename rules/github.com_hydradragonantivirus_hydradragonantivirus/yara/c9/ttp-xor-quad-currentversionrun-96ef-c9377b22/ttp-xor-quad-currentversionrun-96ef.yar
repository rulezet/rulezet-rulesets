rule TTP_XOR_QUAD_CurrentVersionRun_96ef {
  strings:
    $key_96ef = { c5 80 [2] e1 8e [2] ca a2 [2] e4 80 [2] f0 9b [2] ff 81 [2] e1 9c [2] e3 9d [2] f8 9b [2] e4 9c [2] f8 b3 }

  condition:
    any of them
}