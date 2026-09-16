rule TTP_XOR_QUAD_CurrentVersionRun_a260 {
  strings:
    $key_a260 = { f1 0f [2] d5 01 [2] fe 2d [2] d0 0f [2] c4 14 [2] cb 0e [2] d5 13 [2] d7 12 [2] cc 14 [2] d0 13 [2] cc 3c }

  condition:
    any of them
}