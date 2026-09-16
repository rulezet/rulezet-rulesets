rule TTP_XOR_QUAD_CurrentVersionRun_bed5 {
  strings:
    $key_bed5 = { ed ba [2] c9 b4 [2] e2 98 [2] cc ba [2] d8 a1 [2] d7 bb [2] c9 a6 [2] cb a7 [2] d0 a1 [2] cc a6 [2] d0 89 }

  condition:
    any of them
}