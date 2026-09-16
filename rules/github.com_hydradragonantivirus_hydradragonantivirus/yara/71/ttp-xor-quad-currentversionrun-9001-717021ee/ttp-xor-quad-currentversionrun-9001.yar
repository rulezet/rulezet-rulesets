rule TTP_XOR_QUAD_CurrentVersionRun_9001 {
  strings:
    $key_9001 = { c3 6e [2] e7 60 [2] cc 4c [2] e2 6e [2] f6 75 [2] f9 6f [2] e7 72 [2] e5 73 [2] fe 75 [2] e2 72 [2] fe 5d }

  condition:
    any of them
}