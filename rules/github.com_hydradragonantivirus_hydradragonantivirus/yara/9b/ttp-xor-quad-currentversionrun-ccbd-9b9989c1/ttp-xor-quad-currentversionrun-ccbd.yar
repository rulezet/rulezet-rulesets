rule TTP_XOR_QUAD_CurrentVersionRun_ccbd {
  strings:
    $key_ccbd = { 9f d2 [2] bb dc [2] 90 f0 [2] be d2 [2] aa c9 [2] a5 d3 [2] bb ce [2] b9 cf [2] a2 c9 [2] be ce [2] a2 e1 }

  condition:
    any of them
}