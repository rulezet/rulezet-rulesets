rule TTP_XOR_QUAD_CurrentVersionRun_7cbd {
  strings:
    $key_7cbd = { 2f d2 [2] 0b dc [2] 20 f0 [2] 0e d2 [2] 1a c9 [2] 15 d3 [2] 0b ce [2] 09 cf [2] 12 c9 [2] 0e ce [2] 12 e1 }

  condition:
    any of them
}