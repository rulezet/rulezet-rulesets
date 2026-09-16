rule TTP_XOR_QUAD_CurrentVersionRun_6fbc {
  strings:
    $key_6fbc = { 3c d3 [2] 18 dd [2] 33 f1 [2] 1d d3 [2] 09 c8 [2] 06 d2 [2] 18 cf [2] 1a ce [2] 01 c8 [2] 1d cf [2] 01 e0 }

  condition:
    any of them
}