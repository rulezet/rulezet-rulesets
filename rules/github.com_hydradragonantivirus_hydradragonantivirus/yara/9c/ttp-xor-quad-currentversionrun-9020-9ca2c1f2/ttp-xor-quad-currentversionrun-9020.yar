rule TTP_XOR_QUAD_CurrentVersionRun_9020 {
  strings:
    $key_9020 = { c3 4f [2] e7 41 [2] cc 6d [2] e2 4f [2] f6 54 [2] f9 4e [2] e7 53 [2] e5 52 [2] fe 54 [2] e2 53 [2] fe 7c }

  condition:
    any of them
}