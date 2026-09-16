rule TTP_XOR_QUAD_CurrentVersionRun_05a0 {
  strings:
    $key_05a0 = { 56 cf [2] 72 c1 [2] 59 ed [2] 77 cf [2] 63 d4 [2] 6c ce [2] 72 d3 [2] 70 d2 [2] 6b d4 [2] 77 d3 [2] 6b fc }

  condition:
    any of them
}