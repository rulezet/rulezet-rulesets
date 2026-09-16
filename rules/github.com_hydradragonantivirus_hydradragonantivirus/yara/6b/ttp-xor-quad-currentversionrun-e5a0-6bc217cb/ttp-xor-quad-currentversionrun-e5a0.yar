rule TTP_XOR_QUAD_CurrentVersionRun_e5a0 {
  strings:
    $key_e5a0 = { b6 cf [2] 92 c1 [2] b9 ed [2] 97 cf [2] 83 d4 [2] 8c ce [2] 92 d3 [2] 90 d2 [2] 8b d4 [2] 97 d3 [2] 8b fc }

  condition:
    any of them
}