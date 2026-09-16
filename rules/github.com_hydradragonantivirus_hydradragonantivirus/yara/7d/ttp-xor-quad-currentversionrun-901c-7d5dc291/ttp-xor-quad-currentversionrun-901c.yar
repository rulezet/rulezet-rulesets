rule TTP_XOR_QUAD_CurrentVersionRun_901c {
  strings:
    $key_901c = { c3 73 [2] e7 7d [2] cc 51 [2] e2 73 [2] f6 68 [2] f9 72 [2] e7 6f [2] e5 6e [2] fe 68 [2] e2 6f [2] fe 40 }

  condition:
    any of them
}