rule TTP_XOR_QUAD_CurrentVersionRun_9601 {
  strings:
    $key_9601 = { c5 6e [2] e1 60 [2] ca 4c [2] e4 6e [2] f0 75 [2] ff 6f [2] e1 72 [2] e3 73 [2] f8 75 [2] e4 72 [2] f8 5d }

  condition:
    any of them
}