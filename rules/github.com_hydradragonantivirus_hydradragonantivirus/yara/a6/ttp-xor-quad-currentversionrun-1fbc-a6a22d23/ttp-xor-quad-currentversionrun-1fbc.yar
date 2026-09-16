rule TTP_XOR_QUAD_CurrentVersionRun_1fbc {
  strings:
    $key_1fbc = { 4c d3 [2] 68 dd [2] 43 f1 [2] 6d d3 [2] 79 c8 [2] 76 d2 [2] 68 cf [2] 6a ce [2] 71 c8 [2] 6d cf [2] 71 e0 }

  condition:
    any of them
}