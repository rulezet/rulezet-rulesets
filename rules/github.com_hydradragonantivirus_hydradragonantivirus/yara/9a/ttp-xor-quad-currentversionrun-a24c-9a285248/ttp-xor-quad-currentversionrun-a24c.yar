rule TTP_XOR_QUAD_CurrentVersionRun_a24c {
  strings:
    $key_a24c = { f1 23 [2] d5 2d [2] fe 01 [2] d0 23 [2] c4 38 [2] cb 22 [2] d5 3f [2] d7 3e [2] cc 38 [2] d0 3f [2] cc 10 }

  condition:
    any of them
}