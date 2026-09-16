rule TTP_XOR_QUAD_CurrentVersionRun_9621 {
  strings:
    $key_9621 = { c5 4e [2] e1 40 [2] ca 6c [2] e4 4e [2] f0 55 [2] ff 4f [2] e1 52 [2] e3 53 [2] f8 55 [2] e4 52 [2] f8 7d }

  condition:
    any of them
}