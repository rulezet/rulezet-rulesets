rule TTP_XOR_QUAD_CurrentVersionRun_5ebc {
  strings:
    $key_5ebc = { 0d d3 [2] 29 dd [2] 02 f1 [2] 2c d3 [2] 38 c8 [2] 37 d2 [2] 29 cf [2] 2b ce [2] 30 c8 [2] 2c cf [2] 30 e0 }

  condition:
    any of them
}