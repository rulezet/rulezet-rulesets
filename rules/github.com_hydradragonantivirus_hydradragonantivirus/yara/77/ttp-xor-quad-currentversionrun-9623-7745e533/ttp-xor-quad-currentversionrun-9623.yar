rule TTP_XOR_QUAD_CurrentVersionRun_9623 {
  strings:
    $key_9623 = { c5 4c [2] e1 42 [2] ca 6e [2] e4 4c [2] f0 57 [2] ff 4d [2] e1 50 [2] e3 51 [2] f8 57 [2] e4 50 [2] f8 7f }

  condition:
    any of them
}