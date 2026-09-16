rule TTP_XOR_QUAD_CurrentVersionRun_be68 {
  strings:
    $key_be68 = { ed 07 [2] c9 09 [2] e2 25 [2] cc 07 [2] d8 1c [2] d7 06 [2] c9 1b [2] cb 1a [2] d0 1c [2] cc 1b [2] d0 34 }

  condition:
    any of them
}