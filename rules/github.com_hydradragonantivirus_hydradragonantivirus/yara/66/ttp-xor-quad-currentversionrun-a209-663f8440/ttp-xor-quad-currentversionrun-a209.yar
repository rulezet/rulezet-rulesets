rule TTP_XOR_QUAD_CurrentVersionRun_a209 {
  strings:
    $key_a209 = { f1 66 [2] d5 68 [2] fe 44 [2] d0 66 [2] c4 7d [2] cb 67 [2] d5 7a [2] d7 7b [2] cc 7d [2] d0 7a [2] cc 55 }

  condition:
    any of them
}