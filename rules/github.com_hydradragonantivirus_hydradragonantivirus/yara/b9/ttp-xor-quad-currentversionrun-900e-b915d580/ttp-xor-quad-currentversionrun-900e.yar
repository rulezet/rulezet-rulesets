rule TTP_XOR_QUAD_CurrentVersionRun_900e {
  strings:
    $key_900e = { c3 61 [2] e7 6f [2] cc 43 [2] e2 61 [2] f6 7a [2] f9 60 [2] e7 7d [2] e5 7c [2] fe 7a [2] e2 7d [2] fe 52 }

  condition:
    any of them
}