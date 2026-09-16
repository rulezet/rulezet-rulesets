rule TTP_XOR_QUAD_CurrentVersionRun_49bd {
  strings:
    $key_49bd = { 1a d2 [2] 3e dc [2] 15 f0 [2] 3b d2 [2] 2f c9 [2] 20 d3 [2] 3e ce [2] 3c cf [2] 27 c9 [2] 3b ce [2] 27 e1 }

  condition:
    any of them
}