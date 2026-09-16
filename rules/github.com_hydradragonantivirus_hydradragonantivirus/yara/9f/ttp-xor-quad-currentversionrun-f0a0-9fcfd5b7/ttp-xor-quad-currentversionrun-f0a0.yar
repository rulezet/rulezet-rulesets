rule TTP_XOR_QUAD_CurrentVersionRun_f0a0 {
  strings:
    $key_f0a0 = { a3 cf [2] 87 c1 [2] ac ed [2] 82 cf [2] 96 d4 [2] 99 ce [2] 87 d3 [2] 85 d2 [2] 9e d4 [2] 82 d3 [2] 9e fc }

  condition:
    any of them
}