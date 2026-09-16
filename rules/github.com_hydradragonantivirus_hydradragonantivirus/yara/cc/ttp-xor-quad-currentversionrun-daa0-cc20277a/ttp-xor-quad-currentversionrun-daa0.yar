rule TTP_XOR_QUAD_CurrentVersionRun_daa0 {
  strings:
    $key_daa0 = { 89 cf [2] ad c1 [2] 86 ed [2] a8 cf [2] bc d4 [2] b3 ce [2] ad d3 [2] af d2 [2] b4 d4 [2] a8 d3 [2] b4 fc }

  condition:
    any of them
}