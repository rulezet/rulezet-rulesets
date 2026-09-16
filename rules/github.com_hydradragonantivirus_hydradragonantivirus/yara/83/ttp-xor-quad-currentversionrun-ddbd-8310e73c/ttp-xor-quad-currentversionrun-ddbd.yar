rule TTP_XOR_QUAD_CurrentVersionRun_ddbd {
  strings:
    $key_ddbd = { 8e d2 [2] aa dc [2] 81 f0 [2] af d2 [2] bb c9 [2] b4 d3 [2] aa ce [2] a8 cf [2] b3 c9 [2] af ce [2] b3 e1 }

  condition:
    any of them
}