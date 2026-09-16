rule TTP_XOR_QUAD_CurrentVersionRun_69bc {
  strings:
    $key_69bc = { 3a d3 [2] 1e dd [2] 35 f1 [2] 1b d3 [2] 0f c8 [2] 00 d2 [2] 1e cf [2] 1c ce [2] 07 c8 [2] 1b cf [2] 07 e0 }

  condition:
    any of them
}