rule TTP_XOR_QUAD_CurrentVersionRun_fcbd {
  strings:
    $key_fcbd = { af d2 [2] 8b dc [2] a0 f0 [2] 8e d2 [2] 9a c9 [2] 95 d3 [2] 8b ce [2] 89 cf [2] 92 c9 [2] 8e ce [2] 92 e1 }

  condition:
    any of them
}