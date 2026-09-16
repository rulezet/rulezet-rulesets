rule TTP_XOR_QUAD_CurrentVersionRun_a540 {
  strings:
    $key_a540 = { f6 2f [2] d2 21 [2] f9 0d [2] d7 2f [2] c3 34 [2] cc 2e [2] d2 33 [2] d0 32 [2] cb 34 [2] d7 33 [2] cb 1c }

  condition:
    any of them
}