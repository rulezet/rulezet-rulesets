rule TTP_XOR_QUAD_CurrentVersionRun_a2e4 {
  strings:
    $key_a2e4 = { f1 8b [2] d5 85 [2] fe a9 [2] d0 8b [2] c4 90 [2] cb 8a [2] d5 97 [2] d7 96 [2] cc 90 [2] d0 97 [2] cc b8 }

  condition:
    any of them
}