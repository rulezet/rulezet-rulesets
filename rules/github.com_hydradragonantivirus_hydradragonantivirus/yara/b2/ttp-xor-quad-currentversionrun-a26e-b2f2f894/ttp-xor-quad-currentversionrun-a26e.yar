rule TTP_XOR_QUAD_CurrentVersionRun_a26e {
  strings:
    $key_a26e = { f1 01 [2] d5 0f [2] fe 23 [2] d0 01 [2] c4 1a [2] cb 00 [2] d5 1d [2] d7 1c [2] cc 1a [2] d0 1d [2] cc 32 }

  condition:
    any of them
}