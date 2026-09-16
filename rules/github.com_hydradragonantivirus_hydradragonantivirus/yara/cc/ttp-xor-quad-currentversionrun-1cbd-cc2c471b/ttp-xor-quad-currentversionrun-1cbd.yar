rule TTP_XOR_QUAD_CurrentVersionRun_1cbd {
  strings:
    $key_1cbd = { 4f d2 [2] 6b dc [2] 40 f0 [2] 6e d2 [2] 7a c9 [2] 75 d3 [2] 6b ce [2] 69 cf [2] 72 c9 [2] 6e ce [2] 72 e1 }

  condition:
    any of them
}