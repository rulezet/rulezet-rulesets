rule TTP_XOR_QUAD_CurrentVersionRun_ada6 {
  strings:
    $key_ada6 = { fe c9 [2] da c7 [2] f1 eb [2] df c9 [2] cb d2 [2] c4 c8 [2] da d5 [2] d8 d4 [2] c3 d2 [2] df d5 [2] c3 fa }

  condition:
    any of them
}