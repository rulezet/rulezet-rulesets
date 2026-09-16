rule TTP_XOR_QUAD_CurrentVersionRun_907d {
  strings:
    $key_907d = { c3 12 [2] e7 1c [2] cc 30 [2] e2 12 [2] f6 09 [2] f9 13 [2] e7 0e [2] e5 0f [2] fe 09 [2] e2 0e [2] fe 21 }

  condition:
    any of them
}