rule TTP_XOR_QUAD_CurrentVersionRun_be04 {
  strings:
    $key_be04 = { ed 6b [2] c9 65 [2] e2 49 [2] cc 6b [2] d8 70 [2] d7 6a [2] c9 77 [2] cb 76 [2] d0 70 [2] cc 77 [2] d0 58 }

  condition:
    any of them
}