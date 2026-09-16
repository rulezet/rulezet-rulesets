rule TTP_XOR_QUAD_CurrentVersionRun_49a0 {
  strings:
    $key_49a0 = { 1a cf [2] 3e c1 [2] 15 ed [2] 3b cf [2] 2f d4 [2] 20 ce [2] 3e d3 [2] 3c d2 [2] 27 d4 [2] 3b d3 [2] 27 fc }

  condition:
    any of them
}