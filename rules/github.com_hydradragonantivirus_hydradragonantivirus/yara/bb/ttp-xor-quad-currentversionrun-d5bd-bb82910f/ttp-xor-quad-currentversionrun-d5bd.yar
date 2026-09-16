rule TTP_XOR_QUAD_CurrentVersionRun_d5bd {
  strings:
    $key_d5bd = { 86 d2 [2] a2 dc [2] 89 f0 [2] a7 d2 [2] b3 c9 [2] bc d3 [2] a2 ce [2] a0 cf [2] bb c9 [2] a7 ce [2] bb e1 }

  condition:
    any of them
}