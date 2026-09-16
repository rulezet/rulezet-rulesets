rule TTP_XOR_QUAD_CurrentVersionRun_f8a0 {
  strings:
    $key_f8a0 = { ab cf [2] 8f c1 [2] a4 ed [2] 8a cf [2] 9e d4 [2] 91 ce [2] 8f d3 [2] 8d d2 [2] 96 d4 [2] 8a d3 [2] 96 fc }

  condition:
    any of them
}