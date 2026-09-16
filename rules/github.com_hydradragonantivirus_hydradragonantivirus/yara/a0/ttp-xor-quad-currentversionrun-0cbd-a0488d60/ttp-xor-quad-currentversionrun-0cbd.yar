rule TTP_XOR_QUAD_CurrentVersionRun_0cbd {
  strings:
    $key_0cbd = { 5f d2 [2] 7b dc [2] 50 f0 [2] 7e d2 [2] 6a c9 [2] 65 d3 [2] 7b ce [2] 79 cf [2] 62 c9 [2] 7e ce [2] 62 e1 }

  condition:
    any of them
}