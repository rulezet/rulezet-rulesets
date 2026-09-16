rule TTP_XOR_QUAD_CurrentVersionRun_5dbd {
  strings:
    $key_5dbd = { 0e d2 [2] 2a dc [2] 01 f0 [2] 2f d2 [2] 3b c9 [2] 34 d3 [2] 2a ce [2] 28 cf [2] 33 c9 [2] 2f ce [2] 33 e1 }

  condition:
    any of them
}