rule TTP_XOR_QUAD_CurrentVersionRun_39bd {
  strings:
    $key_39bd = { 6a d2 [2] 4e dc [2] 65 f0 [2] 4b d2 [2] 5f c9 [2] 50 d3 [2] 4e ce [2] 4c cf [2] 57 c9 [2] 4b ce [2] 57 e1 }

  condition:
    any of them
}