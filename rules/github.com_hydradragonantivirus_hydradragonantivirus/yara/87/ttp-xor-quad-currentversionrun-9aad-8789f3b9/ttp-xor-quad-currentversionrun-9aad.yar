rule TTP_XOR_QUAD_CurrentVersionRun_9aad {
  strings:
    $key_9aad = { c9 c2 [2] ed cc [2] c6 e0 [2] e8 c2 [2] fc d9 [2] f3 c3 [2] ed de [2] ef df [2] f4 d9 [2] e8 de [2] f4 f1 }

  condition:
    any of them
}