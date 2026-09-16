rule TTP_XOR_QUAD_CurrentVersionRun_bed6 {
  strings:
    $key_bed6 = { ed b9 [2] c9 b7 [2] e2 9b [2] cc b9 [2] d8 a2 [2] d7 b8 [2] c9 a5 [2] cb a4 [2] d0 a2 [2] cc a5 [2] d0 8a }

  condition:
    any of them
}