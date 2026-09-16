rule TTP_XOR_QUAD_CurrentVersionRun_2dbd {
  strings:
    $key_2dbd = { 7e d2 [2] 5a dc [2] 71 f0 [2] 5f d2 [2] 4b c9 [2] 44 d3 [2] 5a ce [2] 58 cf [2] 43 c9 [2] 5f ce [2] 43 e1 }

  condition:
    any of them
}