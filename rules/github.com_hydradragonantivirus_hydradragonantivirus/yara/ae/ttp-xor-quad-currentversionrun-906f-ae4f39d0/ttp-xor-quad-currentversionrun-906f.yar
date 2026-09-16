rule TTP_XOR_QUAD_CurrentVersionRun_906f {
  strings:
    $key_906f = { c3 00 [2] e7 0e [2] cc 22 [2] e2 00 [2] f6 1b [2] f9 01 [2] e7 1c [2] e5 1d [2] fe 1b [2] e2 1c [2] fe 33 }

  condition:
    any of them
}