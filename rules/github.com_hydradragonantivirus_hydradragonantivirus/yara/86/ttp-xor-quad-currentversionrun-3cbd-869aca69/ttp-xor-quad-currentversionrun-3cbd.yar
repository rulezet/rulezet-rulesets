rule TTP_XOR_QUAD_CurrentVersionRun_3cbd {
  strings:
    $key_3cbd = { 6f d2 [2] 4b dc [2] 60 f0 [2] 4e d2 [2] 5a c9 [2] 55 d3 [2] 4b ce [2] 49 cf [2] 52 c9 [2] 4e ce [2] 52 e1 }

  condition:
    any of them
}