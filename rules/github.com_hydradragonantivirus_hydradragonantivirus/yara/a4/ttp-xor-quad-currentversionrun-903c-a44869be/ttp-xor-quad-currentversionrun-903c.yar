rule TTP_XOR_QUAD_CurrentVersionRun_903c {
  strings:
    $key_903c = { c3 53 [2] e7 5d [2] cc 71 [2] e2 53 [2] f6 48 [2] f9 52 [2] e7 4f [2] e5 4e [2] fe 48 [2] e2 4f [2] fe 60 }

  condition:
    any of them
}