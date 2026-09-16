rule TTP_XOR_QUAD_CurrentVersionRun_904c {
  strings:
    $key_904c = { c3 23 [2] e7 2d [2] cc 01 [2] e2 23 [2] f6 38 [2] f9 22 [2] e7 3f [2] e5 3e [2] fe 38 [2] e2 3f [2] fe 10 }

  condition:
    any of them
}