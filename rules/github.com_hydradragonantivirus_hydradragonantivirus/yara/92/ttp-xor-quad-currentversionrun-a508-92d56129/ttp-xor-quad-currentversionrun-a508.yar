rule TTP_XOR_QUAD_CurrentVersionRun_a508 {
  strings:
    $key_a508 = { f6 67 [2] d2 69 [2] f9 45 [2] d7 67 [2] c3 7c [2] cc 66 [2] d2 7b [2] d0 7a [2] cb 7c [2] d7 7b [2] cb 54 }

  condition:
    any of them
}