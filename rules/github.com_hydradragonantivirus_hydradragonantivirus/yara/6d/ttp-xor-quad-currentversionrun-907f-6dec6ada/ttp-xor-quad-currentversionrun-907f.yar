rule TTP_XOR_QUAD_CurrentVersionRun_907f {
  strings:
    $key_907f = { c3 10 [2] e7 1e [2] cc 32 [2] e2 10 [2] f6 0b [2] f9 11 [2] e7 0c [2] e5 0d [2] fe 0b [2] e2 0c [2] fe 23 }

  condition:
    any of them
}