rule TTP_XOR_QUAD_CurrentVersionRun_a2f4 {
  strings:
    $key_a2f4 = { f1 9b [2] d5 95 [2] fe b9 [2] d0 9b [2] c4 80 [2] cb 9a [2] d5 87 [2] d7 86 [2] cc 80 [2] d0 87 [2] cc a8 }

  condition:
    any of them
}