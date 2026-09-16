rule TTP_XOR_QUAD_CurrentVersionRun_a267 {
  strings:
    $key_a267 = { f1 08 [2] d5 06 [2] fe 2a [2] d0 08 [2] c4 13 [2] cb 09 [2] d5 14 [2] d7 15 [2] cc 13 [2] d0 14 [2] cc 3b }

  condition:
    any of them
}