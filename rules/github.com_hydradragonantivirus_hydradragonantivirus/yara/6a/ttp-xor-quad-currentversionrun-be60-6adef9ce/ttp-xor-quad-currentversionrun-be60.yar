rule TTP_XOR_QUAD_CurrentVersionRun_be60 {
  strings:
    $key_be60 = { ed 0f [2] c9 01 [2] e2 2d [2] cc 0f [2] d8 14 [2] d7 0e [2] c9 13 [2] cb 12 [2] d0 14 [2] cc 13 [2] d0 3c }

  condition:
    any of them
}