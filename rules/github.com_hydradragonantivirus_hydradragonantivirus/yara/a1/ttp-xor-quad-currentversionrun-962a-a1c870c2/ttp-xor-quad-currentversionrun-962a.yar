rule TTP_XOR_QUAD_CurrentVersionRun_962a {
  strings:
    $key_962a = { c5 45 [2] e1 4b [2] ca 67 [2] e4 45 [2] f0 5e [2] ff 44 [2] e1 59 [2] e3 58 [2] f8 5e [2] e4 59 [2] f8 76 }

  condition:
    any of them
}