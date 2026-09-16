rule TTP_XOR_QUAD_CurrentVersionRun_66bd {
  strings:
    $key_66bd = { 35 d2 [2] 11 dc [2] 3a f0 [2] 14 d2 [2] 00 c9 [2] 0f d3 [2] 11 ce [2] 13 cf [2] 08 c9 [2] 14 ce [2] 08 e1 }

  condition:
    any of them
}