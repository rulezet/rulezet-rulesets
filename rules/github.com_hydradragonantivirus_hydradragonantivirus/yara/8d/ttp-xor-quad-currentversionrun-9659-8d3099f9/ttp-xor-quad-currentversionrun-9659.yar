rule TTP_XOR_QUAD_CurrentVersionRun_9659 {
  strings:
    $key_9659 = { c5 36 [2] e1 38 [2] ca 14 [2] e4 36 [2] f0 2d [2] ff 37 [2] e1 2a [2] e3 2b [2] f8 2d [2] e4 2a [2] f8 05 }

  condition:
    any of them
}