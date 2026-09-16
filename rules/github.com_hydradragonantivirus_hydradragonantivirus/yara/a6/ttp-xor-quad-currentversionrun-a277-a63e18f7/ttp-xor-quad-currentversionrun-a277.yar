rule TTP_XOR_QUAD_CurrentVersionRun_a277 {
  strings:
    $key_a277 = { f1 18 [2] d5 16 [2] fe 3a [2] d0 18 [2] c4 03 [2] cb 19 [2] d5 04 [2] d7 05 [2] cc 03 [2] d0 04 [2] cc 2b }

  condition:
    any of them
}