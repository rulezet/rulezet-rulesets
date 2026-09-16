rule TTP_XOR_QUAD_CurrentVersionRun_967f {
  strings:
    $key_967f = { c5 10 [2] e1 1e [2] ca 32 [2] e4 10 [2] f0 0b [2] ff 11 [2] e1 0c [2] e3 0d [2] f8 0b [2] e4 0c [2] f8 23 }

  condition:
    any of them
}