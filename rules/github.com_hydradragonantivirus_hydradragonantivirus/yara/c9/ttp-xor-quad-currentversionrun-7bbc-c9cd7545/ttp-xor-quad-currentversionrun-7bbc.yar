rule TTP_XOR_QUAD_CurrentVersionRun_7bbc {
  strings:
    $key_7bbc = { 28 d3 [2] 0c dd [2] 27 f1 [2] 09 d3 [2] 1d c8 [2] 12 d2 [2] 0c cf [2] 0e ce [2] 15 c8 [2] 09 cf [2] 15 e0 }

  condition:
    any of them
}