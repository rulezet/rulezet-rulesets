rule TTP_XOR_QUAD_CurrentVersionRun_9676 {
  strings:
    $key_9676 = { c5 19 [2] e1 17 [2] ca 3b [2] e4 19 [2] f0 02 [2] ff 18 [2] e1 05 [2] e3 04 [2] f8 02 [2] e4 05 [2] f8 2a }

  condition:
    any of them
}