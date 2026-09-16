rule TTP_XOR_QUAD_CurrentVersionRun_f9a1 {
  strings:
    $key_f9a1 = { aa ce [2] 8e c0 [2] a5 ec [2] 8b ce [2] 9f d5 [2] 90 cf [2] 8e d2 [2] 8c d3 [2] 97 d5 [2] 8b d2 [2] 97 fd }

  condition:
    any of them
}