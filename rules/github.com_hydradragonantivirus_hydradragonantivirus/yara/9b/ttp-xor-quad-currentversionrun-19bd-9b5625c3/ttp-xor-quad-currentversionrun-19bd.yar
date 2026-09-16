rule TTP_XOR_QUAD_CurrentVersionRun_19bd {
  strings:
    $key_19bd = { 4a d2 [2] 6e dc [2] 45 f0 [2] 6b d2 [2] 7f c9 [2] 70 d3 [2] 6e ce [2] 6c cf [2] 77 c9 [2] 6b ce [2] 77 e1 }

  condition:
    any of them
}