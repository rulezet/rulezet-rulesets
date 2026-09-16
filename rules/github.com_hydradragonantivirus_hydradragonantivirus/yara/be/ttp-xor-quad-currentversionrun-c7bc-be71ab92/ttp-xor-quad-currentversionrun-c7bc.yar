rule TTP_XOR_QUAD_CurrentVersionRun_c7bc {
  strings:
    $key_c7bc = { 94 d3 [2] b0 dd [2] 9b f1 [2] b5 d3 [2] a1 c8 [2] ae d2 [2] b0 cf [2] b2 ce [2] a9 c8 [2] b5 cf [2] a9 e0 }

  condition:
    any of them
}