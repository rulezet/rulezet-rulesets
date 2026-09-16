rule TTP_XOR_QUAD_CurrentVersionRun_9608 {
  strings:
    $key_9608 = { c5 67 [2] e1 69 [2] ca 45 [2] e4 67 [2] f0 7c [2] ff 66 [2] e1 7b [2] e3 7a [2] f8 7c [2] e4 7b [2] f8 54 }

  condition:
    any of them
}