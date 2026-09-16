rule TTP_XOR_QUAD_CurrentVersionRun_907e {
  strings:
    $key_907e = { c3 11 [2] e7 1f [2] cc 33 [2] e2 11 [2] f6 0a [2] f9 10 [2] e7 0d [2] e5 0c [2] fe 0a [2] e2 0d [2] fe 22 }

  condition:
    any of them
}