rule TTP_XOR_QUAD_CurrentVersionRun_a245 {
  strings:
    $key_a245 = { f1 2a [2] d5 24 [2] fe 08 [2] d0 2a [2] c4 31 [2] cb 2b [2] d5 36 [2] d7 37 [2] cc 31 [2] d0 36 [2] cc 19 }

  condition:
    any of them
}