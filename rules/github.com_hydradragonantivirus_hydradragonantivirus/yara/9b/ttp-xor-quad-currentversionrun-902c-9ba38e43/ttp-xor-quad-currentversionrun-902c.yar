rule TTP_XOR_QUAD_CurrentVersionRun_902c {
  strings:
    $key_902c = { c3 43 [2] e7 4d [2] cc 61 [2] e2 43 [2] f6 58 [2] f9 42 [2] e7 5f [2] e5 5e [2] fe 58 [2] e2 5f [2] fe 70 }

  condition:
    any of them
}