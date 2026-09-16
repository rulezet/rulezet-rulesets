rule TTP_XOR_QUAD_CurrentVersionRun_be5d {
  strings:
    $key_be5d = { ed 32 [2] c9 3c [2] e2 10 [2] cc 32 [2] d8 29 [2] d7 33 [2] c9 2e [2] cb 2f [2] d0 29 [2] cc 2e [2] d0 01 }

  condition:
    any of them
}