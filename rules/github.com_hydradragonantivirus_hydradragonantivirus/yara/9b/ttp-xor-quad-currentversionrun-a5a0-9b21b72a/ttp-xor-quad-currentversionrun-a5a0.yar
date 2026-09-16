rule TTP_XOR_QUAD_CurrentVersionRun_a5a0 {
  strings:
    $key_a5a0 = { f6 cf [2] d2 c1 [2] f9 ed [2] d7 cf [2] c3 d4 [2] cc ce [2] d2 d3 [2] d0 d2 [2] cb d4 [2] d7 d3 [2] cb fc }

  condition:
    any of them
}