rule TTP_XOR_QUAD_CurrentVersionRun_9673 {
  strings:
    $key_9673 = { c5 1c [2] e1 12 [2] ca 3e [2] e4 1c [2] f0 07 [2] ff 1d [2] e1 00 [2] e3 01 [2] f8 07 [2] e4 00 [2] f8 2f }

  condition:
    any of them
}