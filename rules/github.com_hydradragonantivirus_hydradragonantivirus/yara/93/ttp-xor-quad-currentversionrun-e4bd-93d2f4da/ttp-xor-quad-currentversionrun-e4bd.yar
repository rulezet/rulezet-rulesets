rule TTP_XOR_QUAD_CurrentVersionRun_e4bd {
  strings:
    $key_e4bd = { b7 d2 [2] 93 dc [2] b8 f0 [2] 96 d2 [2] 82 c9 [2] 8d d3 [2] 93 ce [2] 91 cf [2] 8a c9 [2] 96 ce [2] 8a e1 }

  condition:
    any of them
}