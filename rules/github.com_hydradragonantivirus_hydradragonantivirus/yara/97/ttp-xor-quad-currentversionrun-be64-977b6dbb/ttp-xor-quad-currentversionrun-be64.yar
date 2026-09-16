rule TTP_XOR_QUAD_CurrentVersionRun_be64 {
  strings:
    $key_be64 = { ed 0b [2] c9 05 [2] e2 29 [2] cc 0b [2] d8 10 [2] d7 0a [2] c9 17 [2] cb 16 [2] d0 10 [2] cc 17 [2] d0 38 }

  condition:
    any of them
}