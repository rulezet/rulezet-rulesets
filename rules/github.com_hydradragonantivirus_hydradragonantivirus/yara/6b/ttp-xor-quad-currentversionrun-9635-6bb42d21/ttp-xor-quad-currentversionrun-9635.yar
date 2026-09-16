rule TTP_XOR_QUAD_CurrentVersionRun_9635 {
  strings:
    $key_9635 = { c5 5a [2] e1 54 [2] ca 78 [2] e4 5a [2] f0 41 [2] ff 5b [2] e1 46 [2] e3 47 [2] f8 41 [2] e4 46 [2] f8 69 }

  condition:
    any of them
}