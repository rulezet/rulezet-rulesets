rule TTP_XOR_QUAD_CurrentVersionRun_9049 {
  strings:
    $key_9049 = { c3 26 [2] e7 28 [2] cc 04 [2] e2 26 [2] f6 3d [2] f9 27 [2] e7 3a [2] e5 3b [2] fe 3d [2] e2 3a [2] fe 15 }

  condition:
    any of them
}