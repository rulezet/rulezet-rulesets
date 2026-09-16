rule TTP_XOR_QUAD_CurrentVersionRun_18a0 {
  strings:
    $key_18a0 = { 4b cf [2] 6f c1 [2] 44 ed [2] 6a cf [2] 7e d4 [2] 71 ce [2] 6f d3 [2] 6d d2 [2] 76 d4 [2] 6a d3 [2] 76 fc }

  condition:
    any of them
}