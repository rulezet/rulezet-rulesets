rule TTP_XOR_QUAD_CurrentVersionRun_9071 {
  strings:
    $key_9071 = { c3 1e [2] e7 10 [2] cc 3c [2] e2 1e [2] f6 05 [2] f9 1f [2] e7 02 [2] e5 03 [2] fe 05 [2] e2 02 [2] fe 2d }

  condition:
    any of them
}