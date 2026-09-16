rule TTP_XOR_QUAD_CurrentVersionRun_a54a {
  strings:
    $key_a54a = { f6 25 [2] d2 2b [2] f9 07 [2] d7 25 [2] c3 3e [2] cc 24 [2] d2 39 [2] d0 38 [2] cb 3e [2] d7 39 [2] cb 16 }

  condition:
    any of them
}