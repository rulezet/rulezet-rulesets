rule TTP_XOR_QUAD_CurrentVersionRun_a52b {
  strings:
    $key_a52b = { f6 44 [2] d2 4a [2] f9 66 [2] d7 44 [2] c3 5f [2] cc 45 [2] d2 58 [2] d0 59 [2] cb 5f [2] d7 58 [2] cb 77 }

  condition:
    any of them
}