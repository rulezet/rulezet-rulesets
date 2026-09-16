rule TTP_XOR_QUAD_CurrentVersionRun_be72 {
  strings:
    $key_be72 = { ed 1d [2] c9 13 [2] e2 3f [2] cc 1d [2] d8 06 [2] d7 1c [2] c9 01 [2] cb 00 [2] d0 06 [2] cc 01 [2] d0 2e }

  condition:
    any of them
}