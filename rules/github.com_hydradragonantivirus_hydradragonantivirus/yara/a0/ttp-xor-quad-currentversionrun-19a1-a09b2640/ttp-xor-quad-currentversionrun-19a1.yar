rule TTP_XOR_QUAD_CurrentVersionRun_19a1 {
  strings:
    $key_19a1 = { 4a ce [2] 6e c0 [2] 45 ec [2] 6b ce [2] 7f d5 [2] 70 cf [2] 6e d2 [2] 6c d3 [2] 77 d5 [2] 6b d2 [2] 77 fd }

  condition:
    any of them
}