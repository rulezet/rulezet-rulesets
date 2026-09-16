rule TTP_XOR_QUAD_CurrentVersionRun_965c {
  strings:
    $key_965c = { c5 33 [2] e1 3d [2] ca 11 [2] e4 33 [2] f0 28 [2] ff 32 [2] e1 2f [2] e3 2e [2] f8 28 [2] e4 2f [2] f8 00 }

  condition:
    any of them
}