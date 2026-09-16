rule TTP_XOR_QUAD_CurrentVersionRun_be39 {
  strings:
    $key_be39 = { ed 56 [2] c9 58 [2] e2 74 [2] cc 56 [2] d8 4d [2] d7 57 [2] c9 4a [2] cb 4b [2] d0 4d [2] cc 4a [2] d0 65 }

  condition:
    any of them
}