rule TTP_XOR_QUAD_CurrentVersionRun_be24 {
  strings:
    $key_be24 = { ed 4b [2] c9 45 [2] e2 69 [2] cc 4b [2] d8 50 [2] d7 4a [2] c9 57 [2] cb 56 [2] d0 50 [2] cc 57 [2] d0 78 }

  condition:
    any of them
}