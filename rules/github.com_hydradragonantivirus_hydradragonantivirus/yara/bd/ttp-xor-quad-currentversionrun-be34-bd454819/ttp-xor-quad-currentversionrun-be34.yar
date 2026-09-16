rule TTP_XOR_QUAD_CurrentVersionRun_be34 {
  strings:
    $key_be34 = { ed 5b [2] c9 55 [2] e2 79 [2] cc 5b [2] d8 40 [2] d7 5a [2] c9 47 [2] cb 46 [2] d0 40 [2] cc 47 [2] d0 68 }

  condition:
    any of them
}