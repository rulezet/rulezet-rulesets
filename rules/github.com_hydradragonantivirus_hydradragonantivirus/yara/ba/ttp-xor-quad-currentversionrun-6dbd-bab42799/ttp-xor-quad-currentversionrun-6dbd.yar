rule TTP_XOR_QUAD_CurrentVersionRun_6dbd {
  strings:
    $key_6dbd = { 3e d2 [2] 1a dc [2] 31 f0 [2] 1f d2 [2] 0b c9 [2] 04 d3 [2] 1a ce [2] 18 cf [2] 03 c9 [2] 1f ce [2] 03 e1 }

  condition:
    any of them
}