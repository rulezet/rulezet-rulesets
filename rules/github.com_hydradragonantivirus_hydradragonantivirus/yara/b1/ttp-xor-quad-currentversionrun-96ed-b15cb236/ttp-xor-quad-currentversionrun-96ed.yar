rule TTP_XOR_QUAD_CurrentVersionRun_96ed {
  strings:
    $key_96ed = { c5 82 [2] e1 8c [2] ca a0 [2] e4 82 [2] f0 99 [2] ff 83 [2] e1 9e [2] e3 9f [2] f8 99 [2] e4 9e [2] f8 b1 }

  condition:
    any of them
}