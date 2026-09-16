rule TTP_XOR_QUAD_CurrentVersionRun_be61 {
  strings:
    $key_be61 = { ed 0e [2] c9 00 [2] e2 2c [2] cc 0e [2] d8 15 [2] d7 0f [2] c9 12 [2] cb 13 [2] d0 15 [2] cc 12 [2] d0 3d }

  condition:
    any of them
}