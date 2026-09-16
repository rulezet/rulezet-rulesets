rule TTP_XOR_QUAD_CurrentVersionRun_7cbc {
  strings:
    $key_7cbc = { 2f d3 [2] 0b dd [2] 20 f1 [2] 0e d3 [2] 1a c8 [2] 15 d2 [2] 0b cf [2] 09 ce [2] 12 c8 [2] 0e cf [2] 12 e0 }

  condition:
    any of them
}