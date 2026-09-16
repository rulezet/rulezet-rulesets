rule TTP_XOR_QUAD_CurrentVersionRun_28bd {
  strings:
    $key_28bd = { 7b d2 [2] 5f dc [2] 74 f0 [2] 5a d2 [2] 4e c9 [2] 41 d3 [2] 5f ce [2] 5d cf [2] 46 c9 [2] 5a ce [2] 46 e1 }

  condition:
    any of them
}