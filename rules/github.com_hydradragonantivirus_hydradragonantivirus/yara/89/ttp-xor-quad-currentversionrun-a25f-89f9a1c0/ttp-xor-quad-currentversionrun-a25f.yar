rule TTP_XOR_QUAD_CurrentVersionRun_a25f {
  strings:
    $key_a25f = { f1 30 [2] d5 3e [2] fe 12 [2] d0 30 [2] c4 2b [2] cb 31 [2] d5 2c [2] d7 2d [2] cc 2b [2] d0 2c [2] cc 03 }

  condition:
    any of them
}