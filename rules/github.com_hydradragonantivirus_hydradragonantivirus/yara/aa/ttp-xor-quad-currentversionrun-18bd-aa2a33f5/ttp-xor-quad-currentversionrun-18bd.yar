rule TTP_XOR_QUAD_CurrentVersionRun_18bd {
  strings:
    $key_18bd = { 4b d2 [2] 6f dc [2] 44 f0 [2] 6a d2 [2] 7e c9 [2] 71 d3 [2] 6f ce [2] 6d cf [2] 76 c9 [2] 6a ce [2] 76 e1 }

  condition:
    any of them
}