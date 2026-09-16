rule TTP_XOR_QUAD_CurrentVersionRun_aebc {
  strings:
    $key_aebc = { fd d3 [2] d9 dd [2] f2 f1 [2] dc d3 [2] c8 c8 [2] c7 d2 [2] d9 cf [2] db ce [2] c0 c8 [2] dc cf [2] c0 e0 }

  condition:
    any of them
}