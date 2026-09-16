rule TTP_XOR_QUAD_CurrentVersionRun_a23f {
  strings:
    $key_a23f = { f1 50 [2] d5 5e [2] fe 72 [2] d0 50 [2] c4 4b [2] cb 51 [2] d5 4c [2] d7 4d [2] cc 4b [2] d0 4c [2] cc 63 }

  condition:
    any of them
}