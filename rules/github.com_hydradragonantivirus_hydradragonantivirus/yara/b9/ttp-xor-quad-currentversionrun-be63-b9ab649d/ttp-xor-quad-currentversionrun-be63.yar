rule TTP_XOR_QUAD_CurrentVersionRun_be63 {
  strings:
    $key_be63 = { ed 0c [2] c9 02 [2] e2 2e [2] cc 0c [2] d8 17 [2] d7 0d [2] c9 10 [2] cb 11 [2] d0 17 [2] cc 10 [2] d0 3f }

  condition:
    any of them
}