rule TTP_XOR_QUAD_CurrentVersionRun_a25b {
  strings:
    $key_a25b = { f1 34 [2] d5 3a [2] fe 16 [2] d0 34 [2] c4 2f [2] cb 35 [2] d5 28 [2] d7 29 [2] cc 2f [2] d0 28 [2] cc 07 }

  condition:
    any of them
}