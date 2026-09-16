rule TTP_XOR_QUAD_CurrentVersionRun_be73 {
  strings:
    $key_be73 = { ed 1c [2] c9 12 [2] e2 3e [2] cc 1c [2] d8 07 [2] d7 1d [2] c9 00 [2] cb 01 [2] d0 07 [2] cc 00 [2] d0 2f }

  condition:
    any of them
}