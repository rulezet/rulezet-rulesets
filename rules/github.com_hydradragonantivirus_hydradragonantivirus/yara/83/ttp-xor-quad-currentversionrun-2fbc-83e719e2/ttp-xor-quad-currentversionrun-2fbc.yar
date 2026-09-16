rule TTP_XOR_QUAD_CurrentVersionRun_2fbc {
  strings:
    $key_2fbc = { 7c d3 [2] 58 dd [2] 73 f1 [2] 5d d3 [2] 49 c8 [2] 46 d2 [2] 58 cf [2] 5a ce [2] 41 c8 [2] 5d cf [2] 41 e0 }

  condition:
    any of them
}