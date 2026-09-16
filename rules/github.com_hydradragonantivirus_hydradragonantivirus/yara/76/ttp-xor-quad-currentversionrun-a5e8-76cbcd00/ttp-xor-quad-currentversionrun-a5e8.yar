rule TTP_XOR_QUAD_CurrentVersionRun_a5e8 {
  strings:
    $key_a5e8 = { f6 87 [2] d2 89 [2] f9 a5 [2] d7 87 [2] c3 9c [2] cc 86 [2] d2 9b [2] d0 9a [2] cb 9c [2] d7 9b [2] cb b4 }

  condition:
    any of them
}