rule TTP_XOR_QUAD_CurrentVersionRun_a5d7 {
  strings:
    $key_a5d7 = { f6 b8 [2] d2 b6 [2] f9 9a [2] d7 b8 [2] c3 a3 [2] cc b9 [2] d2 a4 [2] d0 a5 [2] cb a3 [2] d7 a4 [2] cb 8b }

  condition:
    any of them
}