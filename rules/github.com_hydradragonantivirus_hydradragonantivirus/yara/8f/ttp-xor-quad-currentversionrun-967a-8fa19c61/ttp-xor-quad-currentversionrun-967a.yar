rule TTP_XOR_QUAD_CurrentVersionRun_967a {
  strings:
    $key_967a = { c5 15 [2] e1 1b [2] ca 37 [2] e4 15 [2] f0 0e [2] ff 14 [2] e1 09 [2] e3 08 [2] f8 0e [2] e4 09 [2] f8 26 }

  condition:
    any of them
}