rule TTP_XOR_QUAD_CurrentVersionRun_be0b {
  strings:
    $key_be0b = { ed 64 [2] c9 6a [2] e2 46 [2] cc 64 [2] d8 7f [2] d7 65 [2] c9 78 [2] cb 79 [2] d0 7f [2] cc 78 [2] d0 57 }

  condition:
    any of them
}