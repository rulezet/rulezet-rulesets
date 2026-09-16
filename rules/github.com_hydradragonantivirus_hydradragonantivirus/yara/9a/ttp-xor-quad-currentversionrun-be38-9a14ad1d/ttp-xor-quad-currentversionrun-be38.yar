rule TTP_XOR_QUAD_CurrentVersionRun_be38 {
  strings:
    $key_be38 = { ed 57 [2] c9 59 [2] e2 75 [2] cc 57 [2] d8 4c [2] d7 56 [2] c9 4b [2] cb 4a [2] d0 4c [2] cc 4b [2] d0 64 }

  condition:
    any of them
}