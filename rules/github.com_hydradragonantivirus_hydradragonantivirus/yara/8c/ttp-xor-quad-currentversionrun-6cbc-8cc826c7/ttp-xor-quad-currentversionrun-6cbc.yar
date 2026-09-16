rule TTP_XOR_QUAD_CurrentVersionRun_6cbc {
  strings:
    $key_6cbc = { 3f d3 [2] 1b dd [2] 30 f1 [2] 1e d3 [2] 0a c8 [2] 05 d2 [2] 1b cf [2] 19 ce [2] 02 c8 [2] 1e cf [2] 02 e0 }

  condition:
    any of them
}