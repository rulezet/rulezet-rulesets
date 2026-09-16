rule TTP_XOR_QUAD_CurrentVersionRun_9619 {
  strings:
    $key_9619 = { c5 76 [2] e1 78 [2] ca 54 [2] e4 76 [2] f0 6d [2] ff 77 [2] e1 6a [2] e3 6b [2] f8 6d [2] e4 6a [2] f8 45 }

  condition:
    any of them
}