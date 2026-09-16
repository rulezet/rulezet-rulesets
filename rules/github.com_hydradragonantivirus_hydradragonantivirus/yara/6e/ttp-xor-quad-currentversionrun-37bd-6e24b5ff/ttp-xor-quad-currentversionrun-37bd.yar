rule TTP_XOR_QUAD_CurrentVersionRun_37bd {
  strings:
    $key_37bd = { 64 d2 [2] 40 dc [2] 6b f0 [2] 45 d2 [2] 51 c9 [2] 5e d3 [2] 40 ce [2] 42 cf [2] 59 c9 [2] 45 ce [2] 59 e1 }

  condition:
    any of them
}