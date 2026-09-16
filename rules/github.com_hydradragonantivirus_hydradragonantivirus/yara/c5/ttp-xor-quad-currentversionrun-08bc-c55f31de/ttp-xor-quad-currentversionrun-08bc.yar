rule TTP_XOR_QUAD_CurrentVersionRun_08bc {
  strings:
    $key_08bc = { 5b d3 [2] 7f dd [2] 54 f1 [2] 7a d3 [2] 6e c8 [2] 61 d2 [2] 7f cf [2] 7d ce [2] 66 c8 [2] 7a cf [2] 66 e0 }

  condition:
    any of them
}