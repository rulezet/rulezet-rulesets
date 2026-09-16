rule TTP_XOR_QUAD_CurrentVersionRun_a234 {
  strings:
    $key_a234 = { f1 5b [2] d5 55 [2] fe 79 [2] d0 5b [2] c4 40 [2] cb 5a [2] d5 47 [2] d7 46 [2] cc 40 [2] d0 47 [2] cc 68 }

  condition:
    any of them
}