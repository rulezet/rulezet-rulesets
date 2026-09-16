rule TTP_XOR_QUAD_CurrentVersionRun_39a0 {
  strings:
    $key_39a0 = { 6a cf [2] 4e c1 [2] 65 ed [2] 4b cf [2] 5f d4 [2] 50 ce [2] 4e d3 [2] 4c d2 [2] 57 d4 [2] 4b d3 [2] 57 fc }

  condition:
    any of them
}