rule TTP_XOR_QUAD_CurrentVersionRun_a56e {
  strings:
    $key_a56e = { f6 01 [2] d2 0f [2] f9 23 [2] d7 01 [2] c3 1a [2] cc 00 [2] d2 1d [2] d0 1c [2] cb 1a [2] d7 1d [2] cb 32 }

  condition:
    any of them
}