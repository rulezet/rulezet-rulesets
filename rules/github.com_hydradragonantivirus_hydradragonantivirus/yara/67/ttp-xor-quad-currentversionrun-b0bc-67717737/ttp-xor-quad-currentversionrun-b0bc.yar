rule TTP_XOR_QUAD_CurrentVersionRun_b0bc {
  strings:
    $key_b0bc = { e3 d3 [2] c7 dd [2] ec f1 [2] c2 d3 [2] d6 c8 [2] d9 d2 [2] c7 cf [2] c5 ce [2] de c8 [2] c2 cf [2] de e0 }

  condition:
    any of them
}