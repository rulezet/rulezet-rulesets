rule TTP_XOR_QUAD_CurrentVersionRun_7ca0 {
  strings:
    $key_7ca0 = { 2f cf [2] 0b c1 [2] 20 ed [2] 0e cf [2] 1a d4 [2] 15 ce [2] 0b d3 [2] 09 d2 [2] 12 d4 [2] 0e d3 [2] 12 fc }

  condition:
    any of them
}