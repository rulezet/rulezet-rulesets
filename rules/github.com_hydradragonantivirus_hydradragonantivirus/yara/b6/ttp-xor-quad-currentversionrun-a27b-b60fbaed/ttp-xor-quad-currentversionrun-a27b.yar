rule TTP_XOR_QUAD_CurrentVersionRun_a27b {
  strings:
    $key_a27b = { f1 14 [2] d5 1a [2] fe 36 [2] d0 14 [2] c4 0f [2] cb 15 [2] d5 08 [2] d7 09 [2] cc 0f [2] d0 08 [2] cc 27 }

  condition:
    any of them
}