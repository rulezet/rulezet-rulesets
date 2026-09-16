rule TTP_XOR_QUAD_CurrentVersionRun_fddb {
  strings:
    $key_fddb = { ae b4 [2] 8a ba [2] a1 96 [2] 8f b4 [2] 9b af [2] 94 b5 [2] 8a a8 [2] 88 a9 [2] 93 af [2] 8f a8 [2] 93 87 }

  condition:
    any of them
}