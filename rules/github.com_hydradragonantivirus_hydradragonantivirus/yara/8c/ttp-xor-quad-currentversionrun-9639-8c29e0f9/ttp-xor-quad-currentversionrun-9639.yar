rule TTP_XOR_QUAD_CurrentVersionRun_9639 {
  strings:
    $key_9639 = { c5 56 [2] e1 58 [2] ca 74 [2] e4 56 [2] f0 4d [2] ff 57 [2] e1 4a [2] e3 4b [2] f8 4d [2] e4 4a [2] f8 65 }

  condition:
    any of them
}