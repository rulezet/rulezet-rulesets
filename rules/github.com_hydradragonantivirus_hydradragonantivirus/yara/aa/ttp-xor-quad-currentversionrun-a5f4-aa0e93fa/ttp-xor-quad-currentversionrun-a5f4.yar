rule TTP_XOR_QUAD_CurrentVersionRun_a5f4 {
  strings:
    $key_a5f4 = { f6 9b [2] d2 95 [2] f9 b9 [2] d7 9b [2] c3 80 [2] cc 9a [2] d2 87 [2] d0 86 [2] cb 80 [2] d7 87 [2] cb a8 }

  condition:
    any of them
}