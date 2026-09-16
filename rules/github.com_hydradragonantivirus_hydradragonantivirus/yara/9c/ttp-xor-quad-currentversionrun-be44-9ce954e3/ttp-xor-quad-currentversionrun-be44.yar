rule TTP_XOR_QUAD_CurrentVersionRun_be44 {
  strings:
    $key_be44 = { ed 2b [2] c9 25 [2] e2 09 [2] cc 2b [2] d8 30 [2] d7 2a [2] c9 37 [2] cb 36 [2] d0 30 [2] cc 37 [2] d0 18 }

  condition:
    any of them
}