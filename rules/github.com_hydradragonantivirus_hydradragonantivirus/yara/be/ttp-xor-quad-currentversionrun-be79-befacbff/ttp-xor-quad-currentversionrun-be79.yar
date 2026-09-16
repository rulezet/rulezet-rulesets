rule TTP_XOR_QUAD_CurrentVersionRun_be79 {
  strings:
    $key_be79 = { ed 16 [2] c9 18 [2] e2 34 [2] cc 16 [2] d8 0d [2] d7 17 [2] c9 0a [2] cb 0b [2] d0 0d [2] cc 0a [2] d0 25 }

  condition:
    any of them
}