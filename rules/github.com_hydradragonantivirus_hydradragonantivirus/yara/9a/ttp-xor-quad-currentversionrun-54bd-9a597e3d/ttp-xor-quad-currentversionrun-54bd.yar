rule TTP_XOR_QUAD_CurrentVersionRun_54bd {
  strings:
    $key_54bd = { 07 d2 [2] 23 dc [2] 08 f0 [2] 26 d2 [2] 32 c9 [2] 3d d3 [2] 23 ce [2] 21 cf [2] 3a c9 [2] 26 ce [2] 3a e1 }

  condition:
    any of them
}