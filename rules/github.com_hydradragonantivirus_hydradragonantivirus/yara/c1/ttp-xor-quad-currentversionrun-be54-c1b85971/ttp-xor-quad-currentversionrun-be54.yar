rule TTP_XOR_QUAD_CurrentVersionRun_be54 {
  strings:
    $key_be54 = { ed 3b [2] c9 35 [2] e2 19 [2] cc 3b [2] d8 20 [2] d7 3a [2] c9 27 [2] cb 26 [2] d0 20 [2] cc 27 [2] d0 08 }

  condition:
    any of them
}