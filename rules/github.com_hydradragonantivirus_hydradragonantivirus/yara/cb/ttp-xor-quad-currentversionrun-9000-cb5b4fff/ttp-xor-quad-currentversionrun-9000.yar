rule TTP_XOR_QUAD_CurrentVersionRun_9000 {
  strings:
    $key_9000 = { c3 6f [2] e7 61 [2] cc 4d [2] e2 6f [2] f6 74 [2] f9 6e [2] e7 73 [2] e5 72 [2] fe 74 [2] e2 73 [2] fe 5c }

  condition:
    any of them
}