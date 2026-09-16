rule TTP_XOR_QUAD_CurrentVersionRun_be08 {
  strings:
    $key_be08 = { ed 67 [2] c9 69 [2] e2 45 [2] cc 67 [2] d8 7c [2] d7 66 [2] c9 7b [2] cb 7a [2] d0 7c [2] cc 7b [2] d0 54 }

  condition:
    any of them
}