rule TTP_XOR_QUAD_CurrentVersionRun_a3bc {
  strings:
    $key_a3bc = { f0 d3 [2] d4 dd [2] ff f1 [2] d1 d3 [2] c5 c8 [2] ca d2 [2] d4 cf [2] d6 ce [2] cd c8 [2] d1 cf [2] cd e0 }

  condition:
    any of them
}