rule TTP_XOR_QUAD_CurrentVersionRun_962d {
  strings:
    $key_962d = { c5 42 [2] e1 4c [2] ca 60 [2] e4 42 [2] f0 59 [2] ff 43 [2] e1 5e [2] e3 5f [2] f8 59 [2] e4 5e [2] f8 71 }

  condition:
    any of them
}