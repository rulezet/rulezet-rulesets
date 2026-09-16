rule TTP_XOR_QUAD_CurrentVersionRun_44bd {
  strings:
    $key_44bd = { 17 d2 [2] 33 dc [2] 18 f0 [2] 36 d2 [2] 22 c9 [2] 2d d3 [2] 33 ce [2] 31 cf [2] 2a c9 [2] 36 ce [2] 2a e1 }

  condition:
    any of them
}