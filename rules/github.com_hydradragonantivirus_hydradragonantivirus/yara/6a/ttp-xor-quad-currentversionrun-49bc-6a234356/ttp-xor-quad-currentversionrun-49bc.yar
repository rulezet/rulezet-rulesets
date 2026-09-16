rule TTP_XOR_QUAD_CurrentVersionRun_49bc {
  strings:
    $key_49bc = { 1a d3 [2] 3e dd [2] 15 f1 [2] 3b d3 [2] 2f c8 [2] 20 d2 [2] 3e cf [2] 3c ce [2] 27 c8 [2] 3b cf [2] 27 e0 }

  condition:
    any of them
}