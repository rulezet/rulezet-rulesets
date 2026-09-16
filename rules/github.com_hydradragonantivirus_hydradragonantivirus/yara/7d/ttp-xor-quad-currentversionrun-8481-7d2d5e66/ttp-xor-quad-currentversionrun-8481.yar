rule TTP_XOR_QUAD_CurrentVersionRun_8481 {
  strings:
    $key_8481 = { d7 ee [2] f3 e0 [2] d8 cc [2] f6 ee [2] e2 f5 [2] ed ef [2] f3 f2 [2] f1 f3 [2] ea f5 [2] f6 f2 [2] ea dd }

  condition:
    any of them
}