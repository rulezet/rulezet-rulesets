rule TTP_XOR_QUAD_CurrentVersionRun_a55a {
  strings:
    $key_a55a = { f6 35 [2] d2 3b [2] f9 17 [2] d7 35 [2] c3 2e [2] cc 34 [2] d2 29 [2] d0 28 [2] cb 2e [2] d7 29 [2] cb 06 }

  condition:
    any of them
}