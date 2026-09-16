rule TTP_XOR_QUAD_CurrentVersionRun_19a0 {
  strings:
    $key_19a0 = { 4a cf [2] 6e c1 [2] 45 ed [2] 6b cf [2] 7f d4 [2] 70 ce [2] 6e d3 [2] 6c d2 [2] 77 d4 [2] 6b d3 [2] 77 fc }

  condition:
    any of them
}