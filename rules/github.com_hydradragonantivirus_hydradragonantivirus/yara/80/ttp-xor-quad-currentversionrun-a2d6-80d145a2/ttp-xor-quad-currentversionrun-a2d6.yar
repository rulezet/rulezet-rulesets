rule TTP_XOR_QUAD_CurrentVersionRun_a2d6 {
  strings:
    $key_a2d6 = { f1 b9 [2] d5 b7 [2] fe 9b [2] d0 b9 [2] c4 a2 [2] cb b8 [2] d5 a5 [2] d7 a4 [2] cc a2 [2] d0 a5 [2] cc 8a }

  condition:
    any of them
}