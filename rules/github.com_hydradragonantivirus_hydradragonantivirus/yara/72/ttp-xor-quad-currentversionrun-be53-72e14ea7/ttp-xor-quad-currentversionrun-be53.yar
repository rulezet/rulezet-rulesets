rule TTP_XOR_QUAD_CurrentVersionRun_be53 {
  strings:
    $key_be53 = { ed 3c [2] c9 32 [2] e2 1e [2] cc 3c [2] d8 27 [2] d7 3d [2] c9 20 [2] cb 21 [2] d0 27 [2] cc 20 [2] d0 0f }

  condition:
    any of them
}