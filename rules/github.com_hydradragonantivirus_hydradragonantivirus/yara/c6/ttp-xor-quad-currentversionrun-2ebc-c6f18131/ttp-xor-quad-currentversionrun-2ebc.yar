rule TTP_XOR_QUAD_CurrentVersionRun_2ebc {
  strings:
    $key_2ebc = { 7d d3 [2] 59 dd [2] 72 f1 [2] 5c d3 [2] 48 c8 [2] 47 d2 [2] 59 cf [2] 5b ce [2] 40 c8 [2] 5c cf [2] 40 e0 }

  condition:
    any of them
}