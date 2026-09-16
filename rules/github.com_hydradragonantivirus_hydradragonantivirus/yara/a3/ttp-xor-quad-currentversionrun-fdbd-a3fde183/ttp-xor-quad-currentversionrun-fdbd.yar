rule TTP_XOR_QUAD_CurrentVersionRun_fdbd {
  strings:
    $key_fdbd = { ae d2 [2] 8a dc [2] a1 f0 [2] 8f d2 [2] 9b c9 [2] 94 d3 [2] 8a ce [2] 88 cf [2] 93 c9 [2] 8f ce [2] 93 e1 }

  condition:
    any of them
}