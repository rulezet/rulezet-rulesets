rule TTP_XOR_QUAD_CurrentVersionRun_a539 {
  strings:
    $key_a539 = { f6 56 [2] d2 58 [2] f9 74 [2] d7 56 [2] c3 4d [2] cc 57 [2] d2 4a [2] d0 4b [2] cb 4d [2] d7 4a [2] cb 65 }

  condition:
    any of them
}