rule TTP_XOR_QUAD_CurrentVersionRun_ada5 {
  strings:
    $key_ada5 = { fe ca [2] da c4 [2] f1 e8 [2] df ca [2] cb d1 [2] c4 cb [2] da d6 [2] d8 d7 [2] c3 d1 [2] df d6 [2] c3 f9 }

  condition:
    any of them
}