rule TTP_XOR_QUAD_CurrentVersionRun_f8bc {
  strings:
    $key_f8bc = { ab d3 [2] 8f dd [2] a4 f1 [2] 8a d3 [2] 9e c8 [2] 91 d2 [2] 8f cf [2] 8d ce [2] 96 c8 [2] 8a cf [2] 96 e0 }

  condition:
    any of them
}