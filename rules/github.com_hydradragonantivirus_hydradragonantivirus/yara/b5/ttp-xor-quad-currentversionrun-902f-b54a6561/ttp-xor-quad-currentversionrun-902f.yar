rule TTP_XOR_QUAD_CurrentVersionRun_902f {
  strings:
    $key_902f = { c3 40 [2] e7 4e [2] cc 62 [2] e2 40 [2] f6 5b [2] f9 41 [2] e7 5c [2] e5 5d [2] fe 5b [2] e2 5c [2] fe 73 }

  condition:
    any of them
}