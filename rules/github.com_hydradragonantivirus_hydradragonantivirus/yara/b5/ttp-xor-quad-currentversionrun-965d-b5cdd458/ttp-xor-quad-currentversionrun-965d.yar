rule TTP_XOR_QUAD_CurrentVersionRun_965d {
  strings:
    $key_965d = { c5 32 [2] e1 3c [2] ca 10 [2] e4 32 [2] f0 29 [2] ff 33 [2] e1 2e [2] e3 2f [2] f8 29 [2] e4 2e [2] f8 01 }

  condition:
    any of them
}