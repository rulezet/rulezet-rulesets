rule TTP_XOR_QUAD_CurrentVersionRun_963e {
  strings:
    $key_963e = { c5 51 [2] e1 5f [2] ca 73 [2] e4 51 [2] f0 4a [2] ff 50 [2] e1 4d [2] e3 4c [2] f8 4a [2] e4 4d [2] f8 62 }

  condition:
    any of them
}