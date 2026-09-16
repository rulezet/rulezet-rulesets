rule TTP_XOR_QUAD_CurrentVersionRun_9fad {
  strings:
    $key_9fad = { cc c2 [2] e8 cc [2] c3 e0 [2] ed c2 [2] f9 d9 [2] f6 c3 [2] e8 de [2] ea df [2] f1 d9 [2] ed de [2] f1 f1 }

  condition:
    any of them
}