rule TTP_XOR_QUAD_CurrentVersionRun_5cbd {
  strings:
    $key_5cbd = { 0f d2 [2] 2b dc [2] 00 f0 [2] 2e d2 [2] 3a c9 [2] 35 d3 [2] 2b ce [2] 29 cf [2] 32 c9 [2] 2e ce [2] 32 e1 }

  condition:
    any of them
}