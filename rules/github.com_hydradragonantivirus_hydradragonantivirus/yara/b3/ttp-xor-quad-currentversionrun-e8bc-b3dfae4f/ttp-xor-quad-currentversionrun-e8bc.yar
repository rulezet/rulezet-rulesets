rule TTP_XOR_QUAD_CurrentVersionRun_e8bc {
  strings:
    $key_e8bc = { bb d3 [2] 9f dd [2] b4 f1 [2] 9a d3 [2] 8e c8 [2] 81 d2 [2] 9f cf [2] 9d ce [2] 86 c8 [2] 9a cf [2] 86 e0 }

  condition:
    any of them
}