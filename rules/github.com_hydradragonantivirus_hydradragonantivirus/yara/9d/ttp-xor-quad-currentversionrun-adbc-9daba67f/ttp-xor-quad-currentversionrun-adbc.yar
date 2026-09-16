rule TTP_XOR_QUAD_CurrentVersionRun_adbc {
  strings:
    $key_adbc = { fe d3 [2] da dd [2] f1 f1 [2] df d3 [2] cb c8 [2] c4 d2 [2] da cf [2] d8 ce [2] c3 c8 [2] df cf [2] c3 e0 }

  condition:
    any of them
}