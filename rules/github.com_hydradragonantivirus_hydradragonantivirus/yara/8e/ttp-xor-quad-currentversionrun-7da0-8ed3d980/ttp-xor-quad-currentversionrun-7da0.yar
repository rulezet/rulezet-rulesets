rule TTP_XOR_QUAD_CurrentVersionRun_7da0 {
  strings:
    $key_7da0 = { 2e cf [2] 0a c1 [2] 21 ed [2] 0f cf [2] 1b d4 [2] 14 ce [2] 0a d3 [2] 08 d2 [2] 13 d4 [2] 0f d3 [2] 13 fc }

  condition:
    any of them
}