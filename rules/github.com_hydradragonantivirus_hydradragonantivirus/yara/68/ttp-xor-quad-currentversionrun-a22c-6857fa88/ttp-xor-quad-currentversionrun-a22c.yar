rule TTP_XOR_QUAD_CurrentVersionRun_a22c {
  strings:
    $key_a22c = { f1 43 [2] d5 4d [2] fe 61 [2] d0 43 [2] c4 58 [2] cb 42 [2] d5 5f [2] d7 5e [2] cc 58 [2] d0 5f [2] cc 70 }

  condition:
    any of them
}