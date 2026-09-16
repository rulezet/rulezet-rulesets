rule TTP_XOR_QUAD_CurrentVersionRun_06bd {
  strings:
    $key_06bd = { 55 d2 [2] 71 dc [2] 5a f0 [2] 74 d2 [2] 60 c9 [2] 6f d3 [2] 71 ce [2] 73 cf [2] 68 c9 [2] 74 ce [2] 68 e1 }

  condition:
    any of them
}