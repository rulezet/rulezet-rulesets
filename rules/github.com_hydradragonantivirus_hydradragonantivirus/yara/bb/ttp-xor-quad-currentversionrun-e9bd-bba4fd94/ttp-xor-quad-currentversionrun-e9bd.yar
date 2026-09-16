rule TTP_XOR_QUAD_CurrentVersionRun_e9bd {
  strings:
    $key_e9bd = { ba d2 [2] 9e dc [2] b5 f0 [2] 9b d2 [2] 8f c9 [2] 80 d3 [2] 9e ce [2] 9c cf [2] 87 c9 [2] 9b ce [2] 87 e1 }

  condition:
    any of them
}