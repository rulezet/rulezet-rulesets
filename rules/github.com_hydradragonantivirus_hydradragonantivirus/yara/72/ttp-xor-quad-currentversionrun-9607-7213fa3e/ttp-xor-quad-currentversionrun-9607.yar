rule TTP_XOR_QUAD_CurrentVersionRun_9607 {
  strings:
    $key_9607 = { c5 68 [2] e1 66 [2] ca 4a [2] e4 68 [2] f0 73 [2] ff 69 [2] e1 74 [2] e3 75 [2] f8 73 [2] e4 74 [2] f8 5b }

  condition:
    any of them
}