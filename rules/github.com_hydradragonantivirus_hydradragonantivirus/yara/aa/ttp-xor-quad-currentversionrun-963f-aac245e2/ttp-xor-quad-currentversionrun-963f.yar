rule TTP_XOR_QUAD_CurrentVersionRun_963f {
  strings:
    $key_963f = { c5 50 [2] e1 5e [2] ca 72 [2] e4 50 [2] f0 4b [2] ff 51 [2] e1 4c [2] e3 4d [2] f8 4b [2] e4 4c [2] f8 63 }

  condition:
    any of them
}