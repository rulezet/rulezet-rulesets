rule TTP_XOR_QUAD_CurrentVersionRun_964f {
  strings:
    $key_964f = { c5 20 [2] e1 2e [2] ca 02 [2] e4 20 [2] f0 3b [2] ff 21 [2] e1 3c [2] e3 3d [2] f8 3b [2] e4 3c [2] f8 13 }

  condition:
    any of them
}