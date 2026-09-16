rule TTP_XOR_QUAD_CurrentVersionRun_a26f {
  strings:
    $key_a26f = { f1 00 [2] d5 0e [2] fe 22 [2] d0 00 [2] c4 1b [2] cb 01 [2] d5 1c [2] d7 1d [2] cc 1b [2] d0 1c [2] cc 33 }

  condition:
    any of them
}