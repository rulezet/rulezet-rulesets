rule TTP_XOR_QUAD_CurrentVersionRun_904e {
  strings:
    $key_904e = { c3 21 [2] e7 2f [2] cc 03 [2] e2 21 [2] f6 3a [2] f9 20 [2] e7 3d [2] e5 3c [2] fe 3a [2] e2 3d [2] fe 12 }

  condition:
    any of them
}