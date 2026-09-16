rule TTP_XOR_QUAD_CurrentVersionRun_a26b {
  strings:
    $key_a26b = { f1 04 [2] d5 0a [2] fe 26 [2] d0 04 [2] c4 1f [2] cb 05 [2] d5 18 [2] d7 19 [2] cc 1f [2] d0 18 [2] cc 37 }

  condition:
    any of them
}