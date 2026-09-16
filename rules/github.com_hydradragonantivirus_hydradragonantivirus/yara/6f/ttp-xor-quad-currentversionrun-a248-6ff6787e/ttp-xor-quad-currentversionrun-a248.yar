rule TTP_XOR_QUAD_CurrentVersionRun_a248 {
  strings:
    $key_a248 = { f1 27 [2] d5 29 [2] fe 05 [2] d0 27 [2] c4 3c [2] cb 26 [2] d5 3b [2] d7 3a [2] cc 3c [2] d0 3b [2] cc 14 }

  condition:
    any of them
}