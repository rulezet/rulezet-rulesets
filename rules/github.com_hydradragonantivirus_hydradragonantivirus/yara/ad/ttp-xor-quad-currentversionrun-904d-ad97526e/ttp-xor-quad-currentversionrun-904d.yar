rule TTP_XOR_QUAD_CurrentVersionRun_904d {
  strings:
    $key_904d = { c3 22 [2] e7 2c [2] cc 00 [2] e2 22 [2] f6 39 [2] f9 23 [2] e7 3e [2] e5 3f [2] fe 39 [2] e2 3e [2] fe 11 }

  condition:
    any of them
}