rule TTP_XOR_QUAD_CurrentVersionRun_9646 {
  strings:
    $key_9646 = { c5 29 [2] e1 27 [2] ca 0b [2] e4 29 [2] f0 32 [2] ff 28 [2] e1 35 [2] e3 34 [2] f8 32 [2] e4 35 [2] f8 1a }

  condition:
    any of them
}