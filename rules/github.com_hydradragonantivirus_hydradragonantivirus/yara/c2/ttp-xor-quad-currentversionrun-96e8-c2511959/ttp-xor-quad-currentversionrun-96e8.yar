rule TTP_XOR_QUAD_CurrentVersionRun_96e8 {
  strings:
    $key_96e8 = { c5 87 [2] e1 89 [2] ca a5 [2] e4 87 [2] f0 9c [2] ff 86 [2] e1 9b [2] e3 9a [2] f8 9c [2] e4 9b [2] f8 b4 }

  condition:
    any of them
}