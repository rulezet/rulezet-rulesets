rule TTP_XOR_QUAD_CurrentVersionRun_a52c {
  strings:
    $key_a52c = { f6 43 [2] d2 4d [2] f9 61 [2] d7 43 [2] c3 58 [2] cc 42 [2] d2 5f [2] d0 5e [2] cb 58 [2] d7 5f [2] cb 70 }

  condition:
    any of them
}