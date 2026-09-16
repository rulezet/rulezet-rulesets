rule TTP_XOR_QUAD_CurrentVersionRun_59a0 {
  strings:
    $key_59a0 = { 0a cf [2] 2e c1 [2] 05 ed [2] 2b cf [2] 3f d4 [2] 30 ce [2] 2e d3 [2] 2c d2 [2] 37 d4 [2] 2b d3 [2] 37 fc }

  condition:
    any of them
}