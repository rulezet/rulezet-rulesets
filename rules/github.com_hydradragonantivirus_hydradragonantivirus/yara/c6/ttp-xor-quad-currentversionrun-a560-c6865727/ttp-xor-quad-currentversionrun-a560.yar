rule TTP_XOR_QUAD_CurrentVersionRun_a560 {
  strings:
    $key_a560 = { f6 0f [2] d2 01 [2] f9 2d [2] d7 0f [2] c3 14 [2] cc 0e [2] d2 13 [2] d0 12 [2] cb 14 [2] d7 13 [2] cb 3c }

  condition:
    any of them
}