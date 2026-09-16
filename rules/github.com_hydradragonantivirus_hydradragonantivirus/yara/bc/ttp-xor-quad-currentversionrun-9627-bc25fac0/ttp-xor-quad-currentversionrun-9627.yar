rule TTP_XOR_QUAD_CurrentVersionRun_9627 {
  strings:
    $key_9627 = { c5 48 [2] e1 46 [2] ca 6a [2] e4 48 [2] f0 53 [2] ff 49 [2] e1 54 [2] e3 55 [2] f8 53 [2] e4 54 [2] f8 7b }

  condition:
    any of them
}