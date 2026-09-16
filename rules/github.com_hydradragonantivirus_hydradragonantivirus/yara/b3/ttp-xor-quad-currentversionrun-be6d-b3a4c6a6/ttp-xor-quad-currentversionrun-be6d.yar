rule TTP_XOR_QUAD_CurrentVersionRun_be6d {
  strings:
    $key_be6d = { ed 02 [2] c9 0c [2] e2 20 [2] cc 02 [2] d8 19 [2] d7 03 [2] c9 1e [2] cb 1f [2] d0 19 [2] cc 1e [2] d0 31 }

  condition:
    any of them
}