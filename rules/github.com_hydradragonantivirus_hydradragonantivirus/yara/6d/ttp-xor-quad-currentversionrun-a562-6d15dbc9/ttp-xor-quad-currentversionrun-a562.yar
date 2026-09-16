rule TTP_XOR_QUAD_CurrentVersionRun_a562 {
  strings:
    $key_a562 = { f6 0d [2] d2 03 [2] f9 2f [2] d7 0d [2] c3 16 [2] cc 0c [2] d2 11 [2] d0 10 [2] cb 16 [2] d7 11 [2] cb 3e }

  condition:
    any of them
}