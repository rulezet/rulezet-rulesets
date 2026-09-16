rule TTP_XOR_QUAD_CurrentVersionRun_6ca0 {
  strings:
    $key_6ca0 = { 3f cf [2] 1b c1 [2] 30 ed [2] 1e cf [2] 0a d4 [2] 05 ce [2] 1b d3 [2] 19 d2 [2] 02 d4 [2] 1e d3 [2] 02 fc }

  condition:
    any of them
}