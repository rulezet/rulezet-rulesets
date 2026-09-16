rule TTP_XOR_QUAD_CurrentVersionRun_9f9c {
  strings:
    $key_9f9c = { cc f3 [2] e8 fd [2] c3 d1 [2] ed f3 [2] f9 e8 [2] f6 f2 [2] e8 ef [2] ea ee [2] f1 e8 [2] ed ef [2] f1 c0 }

  condition:
    any of them
}