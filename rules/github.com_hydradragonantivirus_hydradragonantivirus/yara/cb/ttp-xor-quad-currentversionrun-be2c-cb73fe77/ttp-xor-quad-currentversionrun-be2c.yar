rule TTP_XOR_QUAD_CurrentVersionRun_be2c {
  strings:
    $key_be2c = { ed 43 [2] c9 4d [2] e2 61 [2] cc 43 [2] d8 58 [2] d7 42 [2] c9 5f [2] cb 5e [2] d0 58 [2] cc 5f [2] d0 70 }

  condition:
    any of them
}