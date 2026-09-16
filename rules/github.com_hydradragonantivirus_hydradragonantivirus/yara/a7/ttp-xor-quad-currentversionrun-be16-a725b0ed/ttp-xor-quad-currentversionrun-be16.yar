rule TTP_XOR_QUAD_CurrentVersionRun_be16 {
  strings:
    $key_be16 = { ed 79 [2] c9 77 [2] e2 5b [2] cc 79 [2] d8 62 [2] d7 78 [2] c9 65 [2] cb 64 [2] d0 62 [2] cc 65 [2] d0 4a }

  condition:
    any of them
}