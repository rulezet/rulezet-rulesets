rule TTP_XOR_QUAD_CurrentVersionRun_be2d {
  strings:
    $key_be2d = { ed 42 [2] c9 4c [2] e2 60 [2] cc 42 [2] d8 59 [2] d7 43 [2] c9 5e [2] cb 5f [2] d0 59 [2] cc 5e [2] d0 71 }

  condition:
    any of them
}