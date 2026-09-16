rule TTP_XOR_QUAD_CurrentVersionRun_a9bb {
  strings:
    $key_a9bb = { fa d4 [2] de da [2] f5 f6 [2] db d4 [2] cf cf [2] c0 d5 [2] de c8 [2] dc c9 [2] c7 cf [2] db c8 [2] c7 e7 }

  condition:
    any of them
}