rule TTP_XOR_QUAD_CurrentVersionRun_63bb {
  strings:
    $key_63bb = { 30 d4 [2] 14 da [2] 3f f6 [2] 11 d4 [2] 05 cf [2] 0a d5 [2] 14 c8 [2] 16 c9 [2] 0d cf [2] 11 c8 [2] 0d e7 }

  condition:
    any of them
}