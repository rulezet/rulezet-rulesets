rule TTP_XOR_QUAD_CurrentVersionRun_a538 {
  strings:
    $key_a538 = { f6 57 [2] d2 59 [2] f9 75 [2] d7 57 [2] c3 4c [2] cc 56 [2] d2 4b [2] d0 4a [2] cb 4c [2] d7 4b [2] cb 64 }

  condition:
    any of them
}