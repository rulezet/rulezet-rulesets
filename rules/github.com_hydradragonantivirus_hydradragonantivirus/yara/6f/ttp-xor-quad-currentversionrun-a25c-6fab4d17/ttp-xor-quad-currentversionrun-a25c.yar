rule TTP_XOR_QUAD_CurrentVersionRun_a25c {
  strings:
    $key_a25c = { f1 33 [2] d5 3d [2] fe 11 [2] d0 33 [2] c4 28 [2] cb 32 [2] d5 2f [2] d7 2e [2] cc 28 [2] d0 2f [2] cc 00 }

  condition:
    any of them
}