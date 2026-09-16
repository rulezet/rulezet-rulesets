rule TTP_XOR_QUAD_CurrentVersionRun_a20b {
  strings:
    $key_a20b = { f1 64 [2] d5 6a [2] fe 46 [2] d0 64 [2] c4 7f [2] cb 65 [2] d5 78 [2] d7 79 [2] cc 7f [2] d0 78 [2] cc 57 }

  condition:
    any of them
}