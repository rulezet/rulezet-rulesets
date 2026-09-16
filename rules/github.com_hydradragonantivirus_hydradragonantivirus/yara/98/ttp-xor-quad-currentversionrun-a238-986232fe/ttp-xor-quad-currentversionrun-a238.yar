rule TTP_XOR_QUAD_CurrentVersionRun_a238 {
  strings:
    $key_a238 = { f1 57 [2] d5 59 [2] fe 75 [2] d0 57 [2] c4 4c [2] cb 56 [2] d5 4b [2] d7 4a [2] cc 4c [2] d0 4b [2] cc 64 }

  condition:
    any of them
}