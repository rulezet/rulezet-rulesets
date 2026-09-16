rule TTP_XOR_QUAD_CurrentVersionRun_9052 {
  strings:
    $key_9052 = { c3 3d [2] e7 33 [2] cc 1f [2] e2 3d [2] f6 26 [2] f9 3c [2] e7 21 [2] e5 20 [2] fe 26 [2] e2 21 [2] fe 0e }

  condition:
    any of them
}