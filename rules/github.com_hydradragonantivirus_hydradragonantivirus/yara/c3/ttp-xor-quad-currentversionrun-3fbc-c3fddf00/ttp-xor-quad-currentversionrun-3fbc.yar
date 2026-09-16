rule TTP_XOR_QUAD_CurrentVersionRun_3fbc {
  strings:
    $key_3fbc = { 6c d3 [2] 48 dd [2] 63 f1 [2] 4d d3 [2] 59 c8 [2] 56 d2 [2] 48 cf [2] 4a ce [2] 51 c8 [2] 4d cf [2] 51 e0 }

  condition:
    any of them
}