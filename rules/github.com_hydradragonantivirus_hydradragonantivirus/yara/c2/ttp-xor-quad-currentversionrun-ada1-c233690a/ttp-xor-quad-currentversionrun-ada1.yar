rule TTP_XOR_QUAD_CurrentVersionRun_ada1 {
  strings:
    $key_ada1 = { fe ce [2] da c0 [2] f1 ec [2] df ce [2] cb d5 [2] c4 cf [2] da d2 [2] d8 d3 [2] c3 d5 [2] df d2 [2] c3 fd }

  condition:
    any of them
}