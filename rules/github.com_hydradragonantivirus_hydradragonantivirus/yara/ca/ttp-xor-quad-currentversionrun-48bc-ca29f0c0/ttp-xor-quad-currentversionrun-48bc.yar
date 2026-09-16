rule TTP_XOR_QUAD_CurrentVersionRun_48bc {
  strings:
    $key_48bc = { 1b d3 [2] 3f dd [2] 14 f1 [2] 3a d3 [2] 2e c8 [2] 21 d2 [2] 3f cf [2] 3d ce [2] 26 c8 [2] 3a cf [2] 26 e0 }

  condition:
    any of them
}