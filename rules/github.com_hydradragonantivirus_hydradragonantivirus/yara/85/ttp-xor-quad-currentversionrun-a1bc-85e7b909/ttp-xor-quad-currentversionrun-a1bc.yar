rule TTP_XOR_QUAD_CurrentVersionRun_a1bc {
  strings:
    $key_a1bc = { f2 d3 [2] d6 dd [2] fd f1 [2] d3 d3 [2] c7 c8 [2] c8 d2 [2] d6 cf [2] d4 ce [2] cf c8 [2] d3 cf [2] cf e0 }

  condition:
    any of them
}