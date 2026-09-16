rule TTP_XOR_QUAD_CurrentVersionRun_9072 {
  strings:
    $key_9072 = { c3 1d [2] e7 13 [2] cc 3f [2] e2 1d [2] f6 06 [2] f9 1c [2] e7 01 [2] e5 00 [2] fe 06 [2] e2 01 [2] fe 2e }

  condition:
    any of them
}