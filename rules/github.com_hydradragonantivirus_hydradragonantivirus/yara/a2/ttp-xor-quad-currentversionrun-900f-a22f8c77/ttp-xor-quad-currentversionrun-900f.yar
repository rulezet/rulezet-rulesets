rule TTP_XOR_QUAD_CurrentVersionRun_900f {
  strings:
    $key_900f = { c3 60 [2] e7 6e [2] cc 42 [2] e2 60 [2] f6 7b [2] f9 61 [2] e7 7c [2] e5 7d [2] fe 7b [2] e2 7c [2] fe 53 }

  condition:
    any of them
}