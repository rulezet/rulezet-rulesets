rule TTP_XOR_QUAD_CurrentVersionRun_a534 {
  strings:
    $key_a534 = { f6 5b [2] d2 55 [2] f9 79 [2] d7 5b [2] c3 40 [2] cc 5a [2] d2 47 [2] d0 46 [2] cb 40 [2] d7 47 [2] cb 68 }

  condition:
    any of them
}