rule TTP_XOR_QUAD_CurrentVersionRun_9a9c {
  strings:
    $key_9a9c = { c9 f3 [2] ed fd [2] c6 d1 [2] e8 f3 [2] fc e8 [2] f3 f2 [2] ed ef [2] ef ee [2] f4 e8 [2] e8 ef [2] f4 c0 }

  condition:
    any of them
}