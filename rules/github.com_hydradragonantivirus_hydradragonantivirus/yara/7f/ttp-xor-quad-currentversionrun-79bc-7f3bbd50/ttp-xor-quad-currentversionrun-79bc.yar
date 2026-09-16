rule TTP_XOR_QUAD_CurrentVersionRun_79bc {
  strings:
    $key_79bc = { 2a d3 [2] 0e dd [2] 25 f1 [2] 0b d3 [2] 1f c8 [2] 10 d2 [2] 0e cf [2] 0c ce [2] 17 c8 [2] 0b cf [2] 17 e0 }

  condition:
    any of them
}