rule TTP_XOR_QUAD_CurrentVersionRun_a568 {
  strings:
    $key_a568 = { f6 07 [2] d2 09 [2] f9 25 [2] d7 07 [2] c3 1c [2] cc 06 [2] d2 1b [2] d0 1a [2] cb 1c [2] d7 1b [2] cb 34 }

  condition:
    any of them
}