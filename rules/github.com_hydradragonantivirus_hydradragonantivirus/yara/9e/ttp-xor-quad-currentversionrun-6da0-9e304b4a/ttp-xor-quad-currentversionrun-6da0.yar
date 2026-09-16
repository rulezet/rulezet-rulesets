rule TTP_XOR_QUAD_CurrentVersionRun_6da0 {
  strings:
    $key_6da0 = { 3e cf [2] 1a c1 [2] 31 ed [2] 1f cf [2] 0b d4 [2] 04 ce [2] 1a d3 [2] 18 d2 [2] 03 d4 [2] 1f d3 [2] 03 fc }

  condition:
    any of them
}