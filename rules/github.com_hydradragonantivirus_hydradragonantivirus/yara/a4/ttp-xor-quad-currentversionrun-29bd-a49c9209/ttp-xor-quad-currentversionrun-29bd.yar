rule TTP_XOR_QUAD_CurrentVersionRun_29bd {
  strings:
    $key_29bd = { 7a d2 [2] 5e dc [2] 75 f0 [2] 5b d2 [2] 4f c9 [2] 40 d3 [2] 5e ce [2] 5c cf [2] 47 c9 [2] 5b ce [2] 47 e1 }

  condition:
    any of them
}