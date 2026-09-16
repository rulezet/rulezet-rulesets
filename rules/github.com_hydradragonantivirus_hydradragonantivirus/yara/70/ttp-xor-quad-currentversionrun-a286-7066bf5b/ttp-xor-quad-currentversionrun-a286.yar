rule TTP_XOR_QUAD_CurrentVersionRun_a286 {
  strings:
    $key_a286 = { f1 e9 [2] d5 e7 [2] fe cb [2] d0 e9 [2] c4 f2 [2] cb e8 [2] d5 f5 [2] d7 f4 [2] cc f2 [2] d0 f5 [2] cc da }

  condition:
    any of them
}