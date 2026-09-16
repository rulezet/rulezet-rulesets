rule TTP_XOR_QUAD_CurrentVersionRun_68bc {
  strings:
    $key_68bc = { 3b d3 [2] 1f dd [2] 34 f1 [2] 1a d3 [2] 0e c8 [2] 01 d2 [2] 1f cf [2] 1d ce [2] 06 c8 [2] 1a cf [2] 06 e0 }

  condition:
    any of them
}