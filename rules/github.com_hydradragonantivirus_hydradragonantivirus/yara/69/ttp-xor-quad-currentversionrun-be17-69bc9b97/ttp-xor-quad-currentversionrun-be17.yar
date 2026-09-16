rule TTP_XOR_QUAD_CurrentVersionRun_be17 {
  strings:
    $key_be17 = { ed 78 [2] c9 76 [2] e2 5a [2] cc 78 [2] d8 63 [2] d7 79 [2] c9 64 [2] cb 65 [2] d0 63 [2] cc 64 [2] d0 4b }

  condition:
    any of them
}