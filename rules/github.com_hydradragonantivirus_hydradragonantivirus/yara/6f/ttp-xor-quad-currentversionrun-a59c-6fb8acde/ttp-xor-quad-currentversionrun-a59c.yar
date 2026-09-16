rule TTP_XOR_QUAD_CurrentVersionRun_a59c {
  strings:
    $key_a59c = { f6 f3 [2] d2 fd [2] f9 d1 [2] d7 f3 [2] c3 e8 [2] cc f2 [2] d2 ef [2] d0 ee [2] cb e8 [2] d7 ef [2] cb c0 }

  condition:
    any of them
}