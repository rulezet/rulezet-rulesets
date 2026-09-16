rule TTP_XOR_QUAD_CurrentVersionRun_9630 {
  strings:
    $key_9630 = { c5 5f [2] e1 51 [2] ca 7d [2] e4 5f [2] f0 44 [2] ff 5e [2] e1 43 [2] e3 42 [2] f8 44 [2] e4 43 [2] f8 6c }

  condition:
    any of them
}