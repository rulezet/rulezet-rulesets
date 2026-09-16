rule TTP_XOR_QUAD_CurrentVersionRun_96f0 {
  strings:
    $key_96f0 = { c5 9f [2] e1 91 [2] ca bd [2] e4 9f [2] f0 84 [2] ff 9e [2] e1 83 [2] e3 82 [2] f8 84 [2] e4 83 [2] f8 ac }

  condition:
    any of them
}