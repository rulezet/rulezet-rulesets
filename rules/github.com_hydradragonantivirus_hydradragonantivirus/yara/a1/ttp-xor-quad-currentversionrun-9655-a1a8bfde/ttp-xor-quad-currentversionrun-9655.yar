rule TTP_XOR_QUAD_CurrentVersionRun_9655 {
  strings:
    $key_9655 = { c5 3a [2] e1 34 [2] ca 18 [2] e4 3a [2] f0 21 [2] ff 3b [2] e1 26 [2] e3 27 [2] f8 21 [2] e4 26 [2] f8 09 }

  condition:
    any of them
}