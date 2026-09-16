rule TTP_XOR_QUAD_CurrentVersionRun_be43 {
  strings:
    $key_be43 = { ed 2c [2] c9 22 [2] e2 0e [2] cc 2c [2] d8 37 [2] d7 2d [2] c9 30 [2] cb 31 [2] d0 37 [2] cc 30 [2] d0 1f }

  condition:
    any of them
}