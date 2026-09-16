rule TTP_XOR_QUAD_CurrentVersionRun_be7e {
  strings:
    $key_be7e = { ed 11 [2] c9 1f [2] e2 33 [2] cc 11 [2] d8 0a [2] d7 10 [2] c9 0d [2] cb 0c [2] d0 0a [2] cc 0d [2] d0 22 }

  condition:
    any of them
}