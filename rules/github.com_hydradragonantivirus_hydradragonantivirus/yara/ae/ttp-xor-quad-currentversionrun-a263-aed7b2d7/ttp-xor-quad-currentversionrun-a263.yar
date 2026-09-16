rule TTP_XOR_QUAD_CurrentVersionRun_a263 {
  strings:
    $key_a263 = { f1 0c [2] d5 02 [2] fe 2e [2] d0 0c [2] c4 17 [2] cb 0d [2] d5 10 [2] d7 11 [2] cc 17 [2] d0 10 [2] cc 3f }

  condition:
    any of them
}