rule TTP_XOR_QUAD_CurrentVersionRun_a2f9 {
  strings:
    $key_a2f9 = { f1 96 [2] d5 98 [2] fe b4 [2] d0 96 [2] c4 8d [2] cb 97 [2] d5 8a [2] d7 8b [2] cc 8d [2] d0 8a [2] cc a5 }

  condition:
    any of them
}