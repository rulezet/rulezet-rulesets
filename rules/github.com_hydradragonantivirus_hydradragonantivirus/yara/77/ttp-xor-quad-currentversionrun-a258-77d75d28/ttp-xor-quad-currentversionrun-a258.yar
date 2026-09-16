rule TTP_XOR_QUAD_CurrentVersionRun_a258 {
  strings:
    $key_a258 = { f1 37 [2] d5 39 [2] fe 15 [2] d0 37 [2] c4 2c [2] cb 36 [2] d5 2b [2] d7 2a [2] cc 2c [2] d0 2b [2] cc 04 }

  condition:
    any of them
}