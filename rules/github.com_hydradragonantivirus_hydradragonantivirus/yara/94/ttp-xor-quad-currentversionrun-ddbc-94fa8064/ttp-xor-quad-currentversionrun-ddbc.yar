rule TTP_XOR_QUAD_CurrentVersionRun_ddbc {
  strings:
    $key_ddbc = { 8e d3 [2] aa dd [2] 81 f1 [2] af d3 [2] bb c8 [2] b4 d2 [2] aa cf [2] a8 ce [2] b3 c8 [2] af cf [2] b3 e0 }

  condition:
    any of them
}