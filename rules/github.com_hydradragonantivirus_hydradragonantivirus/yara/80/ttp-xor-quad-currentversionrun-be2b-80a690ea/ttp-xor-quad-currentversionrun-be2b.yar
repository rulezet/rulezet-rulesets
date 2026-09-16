rule TTP_XOR_QUAD_CurrentVersionRun_be2b {
  strings:
    $key_be2b = { ed 44 [2] c9 4a [2] e2 66 [2] cc 44 [2] d8 5f [2] d7 45 [2] c9 58 [2] cb 59 [2] d0 5f [2] cc 58 [2] d0 77 }

  condition:
    any of them
}