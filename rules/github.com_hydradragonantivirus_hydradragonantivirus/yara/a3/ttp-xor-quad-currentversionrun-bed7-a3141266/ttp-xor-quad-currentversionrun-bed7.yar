rule TTP_XOR_QUAD_CurrentVersionRun_bed7 {
  strings:
    $key_bed7 = { ed b8 [2] c9 b6 [2] e2 9a [2] cc b8 [2] d8 a3 [2] d7 b9 [2] c9 a4 [2] cb a5 [2] d0 a3 [2] cc a4 [2] d0 8b }

  condition:
    any of them
}