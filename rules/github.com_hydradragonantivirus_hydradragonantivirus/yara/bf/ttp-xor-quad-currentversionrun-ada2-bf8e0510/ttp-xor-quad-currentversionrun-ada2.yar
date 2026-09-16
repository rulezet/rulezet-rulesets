rule TTP_XOR_QUAD_CurrentVersionRun_ada2 {
  strings:
    $key_ada2 = { fe cd [2] da c3 [2] f1 ef [2] df cd [2] cb d6 [2] c4 cc [2] da d1 [2] d8 d0 [2] c3 d6 [2] df d1 [2] c3 fe }

  condition:
    any of them
}