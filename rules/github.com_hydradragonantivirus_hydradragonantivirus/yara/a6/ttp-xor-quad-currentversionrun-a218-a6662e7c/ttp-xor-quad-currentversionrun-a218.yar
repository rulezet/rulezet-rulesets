rule TTP_XOR_QUAD_CurrentVersionRun_a218 {
  strings:
    $key_a218 = { f1 77 [2] d5 79 [2] fe 55 [2] d0 77 [2] c4 6c [2] cb 76 [2] d5 6b [2] d7 6a [2] cc 6c [2] d0 6b [2] cc 44 }

  condition:
    any of them
}