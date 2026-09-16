rule TTP_XOR_QUAD_CurrentVersionRun_be55 {
  strings:
    $key_be55 = { ed 3a [2] c9 34 [2] e2 18 [2] cc 3a [2] d8 21 [2] d7 3b [2] c9 26 [2] cb 27 [2] d0 21 [2] cc 26 [2] d0 09 }

  condition:
    any of them
}