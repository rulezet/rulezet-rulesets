rule TTP_XOR_QUAD_CurrentVersionRun_966f {
  strings:
    $key_966f = { c5 00 [2] e1 0e [2] ca 22 [2] e4 00 [2] f0 1b [2] ff 01 [2] e1 1c [2] e3 1d [2] f8 1b [2] e4 1c [2] f8 33 }

  condition:
    any of them
}