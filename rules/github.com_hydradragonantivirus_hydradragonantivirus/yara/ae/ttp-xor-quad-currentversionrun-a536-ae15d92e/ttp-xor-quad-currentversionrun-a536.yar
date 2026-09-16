rule TTP_XOR_QUAD_CurrentVersionRun_a536 {
  strings:
    $key_a536 = { f6 59 [2] d2 57 [2] f9 7b [2] d7 59 [2] c3 42 [2] cc 58 [2] d2 45 [2] d0 44 [2] cb 42 [2] d7 45 [2] cb 6a }

  condition:
    any of them
}