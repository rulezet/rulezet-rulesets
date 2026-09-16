rule TTP_XOR_QUAD_CurrentVersionRun_be13 {
  strings:
    $key_be13 = { ed 7c [2] c9 72 [2] e2 5e [2] cc 7c [2] d8 67 [2] d7 7d [2] c9 60 [2] cb 61 [2] d0 67 [2] cc 60 [2] d0 4f }

  condition:
    any of them
}