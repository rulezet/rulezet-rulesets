rule TTP_XOR_QUAD_CurrentVersionRun_9647 {
  strings:
    $key_9647 = { c5 28 [2] e1 26 [2] ca 0a [2] e4 28 [2] f0 33 [2] ff 29 [2] e1 34 [2] e3 35 [2] f8 33 [2] e4 34 [2] f8 1b }

  condition:
    any of them
}