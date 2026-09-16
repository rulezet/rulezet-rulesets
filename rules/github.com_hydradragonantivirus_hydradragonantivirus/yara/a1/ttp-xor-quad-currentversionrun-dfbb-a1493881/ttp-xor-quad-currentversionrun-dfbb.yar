rule TTP_XOR_QUAD_CurrentVersionRun_dfbb {
  strings:
    $key_dfbb = { 8c d4 [2] a8 da [2] 83 f6 [2] ad d4 [2] b9 cf [2] b6 d5 [2] a8 c8 [2] aa c9 [2] b1 cf [2] ad c8 [2] b1 e7 }

  condition:
    any of them
}