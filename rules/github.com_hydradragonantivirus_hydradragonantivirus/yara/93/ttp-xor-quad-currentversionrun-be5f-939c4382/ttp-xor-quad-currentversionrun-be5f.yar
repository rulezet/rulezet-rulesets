rule TTP_XOR_QUAD_CurrentVersionRun_be5f {
  strings:
    $key_be5f = { ed 30 [2] c9 3e [2] e2 12 [2] cc 30 [2] d8 2b [2] d7 31 [2] c9 2c [2] cb 2d [2] d0 2b [2] cc 2c [2] d0 03 }

  condition:
    any of them
}