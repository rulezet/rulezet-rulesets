rule TTP_XOR_QUAD_CurrentVersionRun_0ebc {
  strings:
    $key_0ebc = { 5d d3 [2] 79 dd [2] 52 f1 [2] 7c d3 [2] 68 c8 [2] 67 d2 [2] 79 cf [2] 7b ce [2] 60 c8 [2] 7c cf [2] 60 e0 }

  condition:
    any of them
}