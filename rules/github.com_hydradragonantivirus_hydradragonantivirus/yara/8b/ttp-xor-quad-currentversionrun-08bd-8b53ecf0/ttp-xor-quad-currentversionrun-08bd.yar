rule TTP_XOR_QUAD_CurrentVersionRun_08bd {
  strings:
    $key_08bd = { 5b d2 [2] 7f dc [2] 54 f0 [2] 7a d2 [2] 6e c9 [2] 61 d3 [2] 7f ce [2] 7d cf [2] 66 c9 [2] 7a ce [2] 66 e1 }

  condition:
    any of them
}