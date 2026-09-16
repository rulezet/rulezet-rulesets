rule TTP_XOR_QUAD_CurrentVersionRun_a205 {
  strings:
    $key_a205 = { f1 6a [2] d5 64 [2] fe 48 [2] d0 6a [2] c4 71 [2] cb 6b [2] d5 76 [2] d7 77 [2] cc 71 [2] d0 76 [2] cc 59 }

  condition:
    any of them
}