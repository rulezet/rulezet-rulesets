rule TTP_XOR_QUAD_CurrentVersionRun_9665 {
  strings:
    $key_9665 = { c5 0a [2] e1 04 [2] ca 28 [2] e4 0a [2] f0 11 [2] ff 0b [2] e1 16 [2] e3 17 [2] f8 11 [2] e4 16 [2] f8 39 }

  condition:
    any of them
}