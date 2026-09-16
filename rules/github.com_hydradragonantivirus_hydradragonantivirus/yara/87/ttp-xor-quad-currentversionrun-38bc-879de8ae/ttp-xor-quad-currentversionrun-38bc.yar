rule TTP_XOR_QUAD_CurrentVersionRun_38bc {
  strings:
    $key_38bc = { 6b d3 [2] 4f dd [2] 64 f1 [2] 4a d3 [2] 5e c8 [2] 51 d2 [2] 4f cf [2] 4d ce [2] 56 c8 [2] 4a cf [2] 56 e0 }

  condition:
    any of them
}