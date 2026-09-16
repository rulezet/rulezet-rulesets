rule TTP_XOR_QUAD_CurrentVersionRun_08a0 {
  strings:
    $key_08a0 = { 5b cf [2] 7f c1 [2] 54 ed [2] 7a cf [2] 6e d4 [2] 61 ce [2] 7f d3 [2] 7d d2 [2] 66 d4 [2] 7a d3 [2] 66 fc }

  condition:
    any of them
}