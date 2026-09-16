rule TTP_XOR_QUAD_CurrentVersionRun_8bad {
  strings:
    $key_8bad = { d8 c2 [2] fc cc [2] d7 e0 [2] f9 c2 [2] ed d9 [2] e2 c3 [2] fc de [2] fe df [2] e5 d9 [2] f9 de [2] e5 f1 }

  condition:
    any of them
}