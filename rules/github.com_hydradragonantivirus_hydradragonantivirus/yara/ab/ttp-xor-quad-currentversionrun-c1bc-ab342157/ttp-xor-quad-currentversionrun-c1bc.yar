rule TTP_XOR_QUAD_CurrentVersionRun_c1bc {
  strings:
    $key_c1bc = { 92 d3 [2] b6 dd [2] 9d f1 [2] b3 d3 [2] a7 c8 [2] a8 d2 [2] b6 cf [2] b4 ce [2] af c8 [2] b3 cf [2] af e0 }

  condition:
    any of them
}