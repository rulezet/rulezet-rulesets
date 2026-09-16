rule TTP_XOR_QUAD_CurrentVersionRun_be1a {
  strings:
    $key_be1a = { ed 75 [2] c9 7b [2] e2 57 [2] cc 75 [2] d8 6e [2] d7 74 [2] c9 69 [2] cb 68 [2] d0 6e [2] cc 69 [2] d0 46 }

  condition:
    any of them
}