rule TTP_XOR_QUAD_CurrentVersionRun_a546 {
  strings:
    $key_a546 = { f6 29 [2] d2 27 [2] f9 0b [2] d7 29 [2] c3 32 [2] cc 28 [2] d2 35 [2] d0 34 [2] cb 32 [2] d7 35 [2] cb 1a }

  condition:
    any of them
}