rule TTP_XOR_QUAD_CurrentVersionRun_a278 {
  strings:
    $key_a278 = { f1 17 [2] d5 19 [2] fe 35 [2] d0 17 [2] c4 0c [2] cb 16 [2] d5 0b [2] d7 0a [2] cc 0c [2] d0 0b [2] cc 24 }

  condition:
    any of them
}