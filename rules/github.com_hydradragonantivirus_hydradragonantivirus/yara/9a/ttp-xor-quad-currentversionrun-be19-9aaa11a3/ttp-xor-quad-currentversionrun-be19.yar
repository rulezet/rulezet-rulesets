rule TTP_XOR_QUAD_CurrentVersionRun_be19 {
  strings:
    $key_be19 = { ed 76 [2] c9 78 [2] e2 54 [2] cc 76 [2] d8 6d [2] d7 77 [2] c9 6a [2] cb 6b [2] d0 6d [2] cc 6a [2] d0 45 }

  condition:
    any of them
}