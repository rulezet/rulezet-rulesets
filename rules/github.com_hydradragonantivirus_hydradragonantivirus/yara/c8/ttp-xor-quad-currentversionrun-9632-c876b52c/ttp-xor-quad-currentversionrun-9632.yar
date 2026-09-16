rule TTP_XOR_QUAD_CurrentVersionRun_9632 {
  strings:
    $key_9632 = { c5 5d [2] e1 53 [2] ca 7f [2] e4 5d [2] f0 46 [2] ff 5c [2] e1 41 [2] e3 40 [2] f8 46 [2] e4 41 [2] f8 6e }

  condition:
    any of them
}