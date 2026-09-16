rule TTP_XOR_QUAD_CurrentVersionRun_39bc {
  strings:
    $key_39bc = { 6a d3 [2] 4e dd [2] 65 f1 [2] 4b d3 [2] 5f c8 [2] 50 d2 [2] 4e cf [2] 4c ce [2] 57 c8 [2] 4b cf [2] 57 e0 }

  condition:
    any of them
}