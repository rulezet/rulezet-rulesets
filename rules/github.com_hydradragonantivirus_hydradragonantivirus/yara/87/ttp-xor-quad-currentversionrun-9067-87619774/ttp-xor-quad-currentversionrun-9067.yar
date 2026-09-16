rule TTP_XOR_QUAD_CurrentVersionRun_9067 {
  strings:
    $key_9067 = { c3 08 [2] e7 06 [2] cc 2a [2] e2 08 [2] f6 13 [2] f9 09 [2] e7 14 [2] e5 15 [2] fe 13 [2] e2 14 [2] fe 3b }

  condition:
    any of them
}