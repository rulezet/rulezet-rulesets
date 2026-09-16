rule TTP_XOR_QUAD_CurrentVersionRun_9667 {
  strings:
    $key_9667 = { c5 08 [2] e1 06 [2] ca 2a [2] e4 08 [2] f0 13 [2] ff 09 [2] e1 14 [2] e3 15 [2] f8 13 [2] e4 14 [2] f8 3b }

  condition:
    any of them
}