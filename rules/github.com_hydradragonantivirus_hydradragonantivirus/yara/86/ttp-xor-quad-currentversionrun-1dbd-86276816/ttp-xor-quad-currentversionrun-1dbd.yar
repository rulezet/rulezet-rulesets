rule TTP_XOR_QUAD_CurrentVersionRun_1dbd {
  strings:
    $key_1dbd = { 4e d2 [2] 6a dc [2] 41 f0 [2] 6f d2 [2] 7b c9 [2] 74 d3 [2] 6a ce [2] 68 cf [2] 73 c9 [2] 6f ce [2] 73 e1 }

  condition:
    any of them
}