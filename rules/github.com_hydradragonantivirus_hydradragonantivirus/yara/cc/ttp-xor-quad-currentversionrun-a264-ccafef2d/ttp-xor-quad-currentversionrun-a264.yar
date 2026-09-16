rule TTP_XOR_QUAD_CurrentVersionRun_a264 {
  strings:
    $key_a264 = { f1 0b [2] d5 05 [2] fe 29 [2] d0 0b [2] c4 10 [2] cb 0a [2] d5 17 [2] d7 16 [2] cc 10 [2] d0 17 [2] cc 38 }

  condition:
    any of them
}