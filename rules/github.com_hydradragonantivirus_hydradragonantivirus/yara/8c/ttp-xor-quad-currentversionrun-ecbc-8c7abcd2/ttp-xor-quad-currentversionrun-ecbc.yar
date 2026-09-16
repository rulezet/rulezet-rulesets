rule TTP_XOR_QUAD_CurrentVersionRun_ecbc {
  strings:
    $key_ecbc = { bf d3 [2] 9b dd [2] b0 f1 [2] 9e d3 [2] 8a c8 [2] 85 d2 [2] 9b cf [2] 99 ce [2] 82 c8 [2] 9e cf [2] 82 e0 }

  condition:
    any of them
}