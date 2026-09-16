rule TTP_XOR_QUAD_CurrentVersionRun_fca0 {
  strings:
    $key_fca0 = { af cf [2] 8b c1 [2] a0 ed [2] 8e cf [2] 9a d4 [2] 95 ce [2] 8b d3 [2] 89 d2 [2] 92 d4 [2] 8e d3 [2] 92 fc }

  condition:
    any of them
}