rule TTP_XOR_QUAD_CurrentVersionRun_34bd {
  strings:
    $key_34bd = { 67 d2 [2] 43 dc [2] 68 f0 [2] 46 d2 [2] 52 c9 [2] 5d d3 [2] 43 ce [2] 41 cf [2] 5a c9 [2] 46 ce [2] 5a e1 }

  condition:
    any of them
}