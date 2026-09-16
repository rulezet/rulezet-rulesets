rule TTP_XOR_QUAD_CurrentVersionRun_966e {
  strings:
    $key_966e = { c5 01 [2] e1 0f [2] ca 23 [2] e4 01 [2] f0 1a [2] ff 00 [2] e1 1d [2] e3 1c [2] f8 1a [2] e4 1d [2] f8 32 }

  condition:
    any of them
}