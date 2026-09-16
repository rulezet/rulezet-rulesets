rule TTP_XOR_QUAD_CurrentVersionRun_96e9 {
  strings:
    $key_96e9 = { c5 86 [2] e1 88 [2] ca a4 [2] e4 86 [2] f0 9d [2] ff 87 [2] e1 9a [2] e3 9b [2] f8 9d [2] e4 9a [2] f8 b5 }

  condition:
    any of them
}