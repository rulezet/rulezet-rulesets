rule TTP_XOR_QUAD_CurrentVersionRun_09a0 {
  strings:
    $key_09a0 = { 5a cf [2] 7e c1 [2] 55 ed [2] 7b cf [2] 6f d4 [2] 60 ce [2] 7e d3 [2] 7c d2 [2] 67 d4 [2] 7b d3 [2] 67 fc }

  condition:
    any of them
}