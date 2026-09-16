rule TTP_XOR_QUAD_CurrentVersionRun_a564 {
  strings:
    $key_a564 = { f6 0b [2] d2 05 [2] f9 29 [2] d7 0b [2] c3 10 [2] cc 0a [2] d2 17 [2] d0 16 [2] cb 10 [2] d7 17 [2] cb 38 }

  condition:
    any of them
}