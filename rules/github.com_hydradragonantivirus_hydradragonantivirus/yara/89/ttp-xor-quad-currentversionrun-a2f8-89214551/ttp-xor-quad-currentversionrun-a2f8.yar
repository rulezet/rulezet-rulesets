rule TTP_XOR_QUAD_CurrentVersionRun_a2f8 {
  strings:
    $key_a2f8 = { f1 97 [2] d5 99 [2] fe b5 [2] d0 97 [2] c4 8c [2] cb 96 [2] d5 8b [2] d7 8a [2] cc 8c [2] d0 8b [2] cc a4 }

  condition:
    any of them
}