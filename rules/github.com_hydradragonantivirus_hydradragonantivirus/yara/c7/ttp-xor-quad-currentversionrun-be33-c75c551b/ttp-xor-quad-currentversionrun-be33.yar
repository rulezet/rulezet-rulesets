rule TTP_XOR_QUAD_CurrentVersionRun_be33 {
  strings:
    $key_be33 = { ed 5c [2] c9 52 [2] e2 7e [2] cc 5c [2] d8 47 [2] d7 5d [2] c9 40 [2] cb 41 [2] d0 47 [2] cc 40 [2] d0 6f }

  condition:
    any of them
}