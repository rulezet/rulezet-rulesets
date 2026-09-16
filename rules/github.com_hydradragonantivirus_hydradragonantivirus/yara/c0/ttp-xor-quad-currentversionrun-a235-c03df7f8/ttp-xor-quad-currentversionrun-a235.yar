rule TTP_XOR_QUAD_CurrentVersionRun_a235 {
  strings:
    $key_a235 = { f1 5a [2] d5 54 [2] fe 78 [2] d0 5a [2] c4 41 [2] cb 5b [2] d5 46 [2] d7 47 [2] cc 41 [2] d0 46 [2] cc 69 }

  condition:
    any of them
}