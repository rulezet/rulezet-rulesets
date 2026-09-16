rule TTP_XOR_QUAD_CurrentVersionRun_971d {
  strings:
    $key_971d = { c4 72 [2] e0 7c [2] cb 50 [2] e5 72 [2] f1 69 [2] fe 73 [2] e0 6e [2] e2 6f [2] f9 69 [2] e5 6e [2] f9 41 }

  condition:
    any of them
}