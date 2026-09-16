rule TTP_XOR_QUAD_CurrentVersionRun_0fbc {
  strings:
    $key_0fbc = { 5c d3 [2] 78 dd [2] 53 f1 [2] 7d d3 [2] 69 c8 [2] 66 d2 [2] 78 cf [2] 7a ce [2] 61 c8 [2] 7d cf [2] 61 e0 }

  condition:
    any of them
}