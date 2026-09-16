rule TTP_XOR_QUAD_CurrentVersionRun_9631 {
  strings:
    $key_9631 = { c5 5e [2] e1 50 [2] ca 7c [2] e4 5e [2] f0 45 [2] ff 5f [2] e1 42 [2] e3 43 [2] f8 45 [2] e4 42 [2] f8 6d }

  condition:
    any of them
}