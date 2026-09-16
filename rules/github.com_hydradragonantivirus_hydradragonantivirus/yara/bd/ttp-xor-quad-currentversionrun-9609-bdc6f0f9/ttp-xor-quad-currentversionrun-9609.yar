rule TTP_XOR_QUAD_CurrentVersionRun_9609 {
  strings:
    $key_9609 = { c5 66 [2] e1 68 [2] ca 44 [2] e4 66 [2] f0 7d [2] ff 67 [2] e1 7a [2] e3 7b [2] f8 7d [2] e4 7a [2] f8 55 }

  condition:
    any of them
}