rule TTP_XOR_QUAD_CurrentVersionRun_24bd {
  strings:
    $key_24bd = { 77 d2 [2] 53 dc [2] 78 f0 [2] 56 d2 [2] 42 c9 [2] 4d d3 [2] 53 ce [2] 51 cf [2] 4a c9 [2] 56 ce [2] 4a e1 }

  condition:
    any of them
}