rule TTP_XOR_QUAD_CurrentVersionRun_a204 {
  strings:
    $key_a204 = { f1 6b [2] d5 65 [2] fe 49 [2] d0 6b [2] c4 70 [2] cb 6a [2] d5 77 [2] d7 76 [2] cc 70 [2] d0 77 [2] cc 58 }

  condition:
    any of them
}