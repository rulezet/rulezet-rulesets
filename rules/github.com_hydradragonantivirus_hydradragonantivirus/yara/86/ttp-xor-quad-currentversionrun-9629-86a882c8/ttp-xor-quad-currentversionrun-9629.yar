rule TTP_XOR_QUAD_CurrentVersionRun_9629 {
  strings:
    $key_9629 = { c5 46 [2] e1 48 [2] ca 64 [2] e4 46 [2] f0 5d [2] ff 47 [2] e1 5a [2] e3 5b [2] f8 5d [2] e4 5a [2] f8 75 }

  condition:
    any of them
}