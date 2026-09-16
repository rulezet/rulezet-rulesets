rule TTP_XOR_QUAD_CurrentVersionRun_9033 {
  strings:
    $key_9033 = { c3 5c [2] e7 52 [2] cc 7e [2] e2 5c [2] f6 47 [2] f9 5d [2] e7 40 [2] e5 41 [2] fe 47 [2] e2 40 [2] fe 6f }

  condition:
    any of them
}