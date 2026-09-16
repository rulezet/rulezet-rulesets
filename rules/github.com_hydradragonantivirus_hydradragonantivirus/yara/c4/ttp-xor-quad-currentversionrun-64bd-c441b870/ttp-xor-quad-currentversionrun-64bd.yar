rule TTP_XOR_QUAD_CurrentVersionRun_64bd {
  strings:
    $key_64bd = { 37 d2 [2] 13 dc [2] 38 f0 [2] 16 d2 [2] 02 c9 [2] 0d d3 [2] 13 ce [2] 11 cf [2] 0a c9 [2] 16 ce [2] 0a e1 }

  condition:
    any of them
}