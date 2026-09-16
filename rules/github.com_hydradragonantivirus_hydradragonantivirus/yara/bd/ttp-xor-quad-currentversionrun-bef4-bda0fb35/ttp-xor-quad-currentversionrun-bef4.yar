rule TTP_XOR_QUAD_CurrentVersionRun_bef4 {
  strings:
    $key_bef4 = { ed 9b [2] c9 95 [2] e2 b9 [2] cc 9b [2] d8 80 [2] d7 9a [2] c9 87 [2] cb 86 [2] d0 80 [2] cc 87 [2] d0 a8 }

  condition:
    any of them
}