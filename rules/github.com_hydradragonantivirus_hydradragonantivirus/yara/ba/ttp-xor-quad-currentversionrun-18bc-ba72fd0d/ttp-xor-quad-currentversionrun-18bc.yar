rule TTP_XOR_QUAD_CurrentVersionRun_18bc {
  strings:
    $key_18bc = { 4b d3 [2] 6f dd [2] 44 f1 [2] 6a d3 [2] 7e c8 [2] 71 d2 [2] 6f cf [2] 6d ce [2] 76 c8 [2] 6a cf [2] 76 e0 }

  condition:
    any of them
}