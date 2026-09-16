rule TTP_XOR_QUAD_CurrentVersionRun_965a {
  strings:
    $key_965a = { c5 35 [2] e1 3b [2] ca 17 [2] e4 35 [2] f0 2e [2] ff 34 [2] e1 29 [2] e3 28 [2] f8 2e [2] e4 29 [2] f8 06 }

  condition:
    any of them
}