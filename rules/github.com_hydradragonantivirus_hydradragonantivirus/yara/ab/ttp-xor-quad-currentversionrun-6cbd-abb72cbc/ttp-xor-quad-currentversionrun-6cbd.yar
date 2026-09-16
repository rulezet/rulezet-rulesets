rule TTP_XOR_QUAD_CurrentVersionRun_6cbd {
  strings:
    $key_6cbd = { 3f d2 [2] 1b dc [2] 30 f0 [2] 1e d2 [2] 0a c9 [2] 05 d3 [2] 1b ce [2] 19 cf [2] 02 c9 [2] 1e ce [2] 02 e1 }

  condition:
    any of them
}