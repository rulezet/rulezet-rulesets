rule TTP_XOR_QUAD_CurrentVersionRun_900c {
  strings:
    $key_900c = { c3 63 [2] e7 6d [2] cc 41 [2] e2 63 [2] f6 78 [2] f9 62 [2] e7 7f [2] e5 7e [2] fe 78 [2] e2 7f [2] fe 50 }

  condition:
    any of them
}