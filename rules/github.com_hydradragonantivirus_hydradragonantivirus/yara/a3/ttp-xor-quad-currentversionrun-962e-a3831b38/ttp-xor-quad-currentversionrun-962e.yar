rule TTP_XOR_QUAD_CurrentVersionRun_962e {
  strings:
    $key_962e = { c5 41 [2] e1 4f [2] ca 63 [2] e4 41 [2] f0 5a [2] ff 40 [2] e1 5d [2] e3 5c [2] f8 5a [2] e4 5d [2] f8 72 }

  condition:
    any of them
}