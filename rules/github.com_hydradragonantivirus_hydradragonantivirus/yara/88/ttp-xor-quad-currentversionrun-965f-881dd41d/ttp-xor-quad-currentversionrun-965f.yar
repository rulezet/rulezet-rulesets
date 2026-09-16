rule TTP_XOR_QUAD_CurrentVersionRun_965f {
  strings:
    $key_965f = { c5 30 [2] e1 3e [2] ca 12 [2] e4 30 [2] f0 2b [2] ff 31 [2] e1 2c [2] e3 2d [2] f8 2b [2] e4 2c [2] f8 03 }

  condition:
    any of them
}