rule TTP_XOR_QUAD_CurrentVersionRun_962c {
  strings:
    $key_962c = { c5 43 [2] e1 4d [2] ca 61 [2] e4 43 [2] f0 58 [2] ff 42 [2] e1 5f [2] e3 5e [2] f8 58 [2] e4 5f [2] f8 70 }

  condition:
    any of them
}