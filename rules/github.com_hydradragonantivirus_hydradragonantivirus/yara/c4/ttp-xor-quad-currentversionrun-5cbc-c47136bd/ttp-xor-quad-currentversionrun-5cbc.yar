rule TTP_XOR_QUAD_CurrentVersionRun_5cbc {
  strings:
    $key_5cbc = { 0f d3 [2] 2b dd [2] 00 f1 [2] 2e d3 [2] 3a c8 [2] 35 d2 [2] 2b cf [2] 29 ce [2] 32 c8 [2] 2e cf [2] 32 e0 }

  condition:
    any of them
}