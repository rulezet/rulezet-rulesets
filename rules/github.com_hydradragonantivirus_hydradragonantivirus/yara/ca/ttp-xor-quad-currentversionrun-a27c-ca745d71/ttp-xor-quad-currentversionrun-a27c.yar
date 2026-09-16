rule TTP_XOR_QUAD_CurrentVersionRun_a27c {
  strings:
    $key_a27c = { f1 13 [2] d5 1d [2] fe 31 [2] d0 13 [2] c4 08 [2] cb 12 [2] d5 0f [2] d7 0e [2] cc 08 [2] d0 0f [2] cc 20 }

  condition:
    any of them
}