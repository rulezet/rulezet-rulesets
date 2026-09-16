rule TTP_XOR_QUAD_CurrentVersionRun_be4c {
  strings:
    $key_be4c = { ed 23 [2] c9 2d [2] e2 01 [2] cc 23 [2] d8 38 [2] d7 22 [2] c9 3f [2] cb 3e [2] d0 38 [2] cc 3f [2] d0 10 }

  condition:
    any of them
}