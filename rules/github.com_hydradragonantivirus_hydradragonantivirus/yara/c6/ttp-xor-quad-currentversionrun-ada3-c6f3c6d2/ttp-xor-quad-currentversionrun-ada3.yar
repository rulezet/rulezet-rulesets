rule TTP_XOR_QUAD_CurrentVersionRun_ada3 {
  strings:
    $key_ada3 = { fe cc [2] da c2 [2] f1 ee [2] df cc [2] cb d7 [2] c4 cd [2] da d0 [2] d8 d1 [2] c3 d7 [2] df d0 [2] c3 ff }

  condition:
    any of them
}