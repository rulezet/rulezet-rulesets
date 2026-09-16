rule TTP_XOR_QUAD_CurrentVersionRun_9603 {
  strings:
    $key_9603 = { c5 6c [2] e1 62 [2] ca 4e [2] e4 6c [2] f0 77 [2] ff 6d [2] e1 70 [2] e3 71 [2] f8 77 [2] e4 70 [2] f8 5f }

  condition:
    any of them
}