rule TTP_XOR_QUAD_CurrentVersionRun_a255 {
  strings:
    $key_a255 = { f1 3a [2] d5 34 [2] fe 18 [2] d0 3a [2] c4 21 [2] cb 3b [2] d5 26 [2] d7 27 [2] cc 21 [2] d0 26 [2] cc 09 }

  condition:
    any of them
}