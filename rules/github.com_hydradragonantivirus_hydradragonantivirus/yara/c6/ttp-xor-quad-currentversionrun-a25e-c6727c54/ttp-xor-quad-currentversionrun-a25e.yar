rule TTP_XOR_QUAD_CurrentVersionRun_a25e {
  strings:
    $key_a25e = { f1 31 [2] d5 3f [2] fe 13 [2] d0 31 [2] c4 2a [2] cb 30 [2] d5 2d [2] d7 2c [2] cc 2a [2] d0 2d [2] cc 02 }

  condition:
    any of them
}