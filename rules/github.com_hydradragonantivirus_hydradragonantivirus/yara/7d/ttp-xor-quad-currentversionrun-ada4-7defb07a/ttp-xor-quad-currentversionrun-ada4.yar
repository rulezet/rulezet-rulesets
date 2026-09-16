rule TTP_XOR_QUAD_CurrentVersionRun_ada4 {
  strings:
    $key_ada4 = { fe cb [2] da c5 [2] f1 e9 [2] df cb [2] cb d0 [2] c4 ca [2] da d7 [2] d8 d6 [2] c3 d0 [2] df d7 [2] c3 f8 }

  condition:
    any of them
}