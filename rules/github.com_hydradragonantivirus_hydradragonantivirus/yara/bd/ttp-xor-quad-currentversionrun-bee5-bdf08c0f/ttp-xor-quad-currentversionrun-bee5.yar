rule TTP_XOR_QUAD_CurrentVersionRun_bee5 {
  strings:
    $key_bee5 = { ed 8a [2] c9 84 [2] e2 a8 [2] cc 8a [2] d8 91 [2] d7 8b [2] c9 96 [2] cb 97 [2] d0 91 [2] cc 96 [2] d0 b9 }

  condition:
    any of them
}