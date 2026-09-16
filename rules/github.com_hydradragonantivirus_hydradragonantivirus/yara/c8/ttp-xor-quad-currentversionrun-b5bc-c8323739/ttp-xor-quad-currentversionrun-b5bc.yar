rule TTP_XOR_QUAD_CurrentVersionRun_b5bc {
  strings:
    $key_b5bc = { e6 d3 [2] c2 dd [2] e9 f1 [2] c7 d3 [2] d3 c8 [2] dc d2 [2] c2 cf [2] c0 ce [2] db c8 [2] c7 cf [2] db e0 }

  condition:
    any of them
}