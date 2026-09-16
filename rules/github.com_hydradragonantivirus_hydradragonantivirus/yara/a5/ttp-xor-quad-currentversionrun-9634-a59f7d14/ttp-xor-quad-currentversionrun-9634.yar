rule TTP_XOR_QUAD_CurrentVersionRun_9634 {
  strings:
    $key_9634 = { c5 5b [2] e1 55 [2] ca 79 [2] e4 5b [2] f0 40 [2] ff 5a [2] e1 47 [2] e3 46 [2] f8 40 [2] e4 47 [2] f8 68 }

  condition:
    any of them
}