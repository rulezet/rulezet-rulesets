rule TTP_XOR_QUAD_CurrentVersionRun_901a {
  strings:
    $key_901a = { c3 75 [2] e7 7b [2] cc 57 [2] e2 75 [2] f6 6e [2] f9 74 [2] e7 69 [2] e5 68 [2] fe 6e [2] e2 69 [2] fe 46 }

  condition:
    any of them
}