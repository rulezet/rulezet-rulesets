rule TTP_XOR_QUAD_CurrentVersionRun_26bd {
  strings:
    $key_26bd = { 75 d2 [2] 51 dc [2] 7a f0 [2] 54 d2 [2] 40 c9 [2] 4f d3 [2] 51 ce [2] 53 cf [2] 48 c9 [2] 54 ce [2] 48 e1 }

  condition:
    any of them
}