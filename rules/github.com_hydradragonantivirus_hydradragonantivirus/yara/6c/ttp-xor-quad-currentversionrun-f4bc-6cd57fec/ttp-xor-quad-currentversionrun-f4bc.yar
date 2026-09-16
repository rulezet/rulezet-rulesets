rule TTP_XOR_QUAD_CurrentVersionRun_f4bc {
  strings:
    $key_f4bc = { a7 d3 [2] 83 dd [2] a8 f1 [2] 86 d3 [2] 92 c8 [2] 9d d2 [2] 83 cf [2] 81 ce [2] 9a c8 [2] 86 cf [2] 9a e0 }

  condition:
    any of them
}