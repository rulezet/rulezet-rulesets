rule TTP_XOR_QUAD_CurrentVersionRun_8b9c {
  strings:
    $key_8b9c = { d8 f3 [2] fc fd [2] d7 d1 [2] f9 f3 [2] ed e8 [2] e2 f2 [2] fc ef [2] fe ee [2] e5 e8 [2] f9 ef [2] e5 c0 }

  condition:
    any of them
}