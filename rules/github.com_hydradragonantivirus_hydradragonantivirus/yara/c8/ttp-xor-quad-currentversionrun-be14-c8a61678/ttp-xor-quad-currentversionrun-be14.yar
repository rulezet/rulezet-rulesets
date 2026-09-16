rule TTP_XOR_QUAD_CurrentVersionRun_be14 {
  strings:
    $key_be14 = { ed 7b [2] c9 75 [2] e2 59 [2] cc 7b [2] d8 60 [2] d7 7a [2] c9 67 [2] cb 66 [2] d0 60 [2] cc 67 [2] d0 48 }

  condition:
    any of them
}