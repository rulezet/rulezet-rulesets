rule TTP_XOR_QUAD_CurrentVersionRun_bed0 {
  strings:
    $key_bed0 = { ed bf [2] c9 b1 [2] e2 9d [2] cc bf [2] d8 a4 [2] d7 be [2] c9 a3 [2] cb a2 [2] d0 a4 [2] cc a3 [2] d0 8c }

  condition:
    any of them
}