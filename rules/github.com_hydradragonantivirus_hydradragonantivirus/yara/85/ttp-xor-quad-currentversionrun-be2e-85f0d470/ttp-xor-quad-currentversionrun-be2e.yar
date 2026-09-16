rule TTP_XOR_QUAD_CurrentVersionRun_be2e {
  strings:
    $key_be2e = { ed 41 [2] c9 4f [2] e2 63 [2] cc 41 [2] d8 5a [2] d7 40 [2] c9 5d [2] cb 5c [2] d0 5a [2] cc 5d [2] d0 72 }

  condition:
    any of them
}