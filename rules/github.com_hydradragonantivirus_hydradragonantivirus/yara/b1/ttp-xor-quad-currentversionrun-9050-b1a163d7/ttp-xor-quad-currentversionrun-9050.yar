rule TTP_XOR_QUAD_CurrentVersionRun_9050 {
  strings:
    $key_9050 = { c3 3f [2] e7 31 [2] cc 1d [2] e2 3f [2] f6 24 [2] f9 3e [2] e7 23 [2] e5 22 [2] fe 24 [2] e2 23 [2] fe 0c }

  condition:
    any of them
}