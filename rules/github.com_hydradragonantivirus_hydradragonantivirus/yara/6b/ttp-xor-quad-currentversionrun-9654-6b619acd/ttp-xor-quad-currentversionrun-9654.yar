rule TTP_XOR_QUAD_CurrentVersionRun_9654 {
  strings:
    $key_9654 = { c5 3b [2] e1 35 [2] ca 19 [2] e4 3b [2] f0 20 [2] ff 3a [2] e1 27 [2] e3 26 [2] f8 20 [2] e4 27 [2] f8 08 }

  condition:
    any of them
}