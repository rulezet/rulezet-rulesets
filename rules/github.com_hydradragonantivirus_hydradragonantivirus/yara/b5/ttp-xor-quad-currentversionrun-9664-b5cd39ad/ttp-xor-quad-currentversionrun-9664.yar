rule TTP_XOR_QUAD_CurrentVersionRun_9664 {
  strings:
    $key_9664 = { c5 0b [2] e1 05 [2] ca 29 [2] e4 0b [2] f0 10 [2] ff 0a [2] e1 17 [2] e3 16 [2] f8 10 [2] e4 17 [2] f8 38 }

  condition:
    any of them
}