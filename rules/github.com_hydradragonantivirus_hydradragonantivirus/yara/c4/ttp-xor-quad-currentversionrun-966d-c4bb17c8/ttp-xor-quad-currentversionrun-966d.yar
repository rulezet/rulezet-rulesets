rule TTP_XOR_QUAD_CurrentVersionRun_966d {
  strings:
    $key_966d = { c5 02 [2] e1 0c [2] ca 20 [2] e4 02 [2] f0 19 [2] ff 03 [2] e1 1e [2] e3 1f [2] f8 19 [2] e4 1e [2] f8 31 }

  condition:
    any of them
}