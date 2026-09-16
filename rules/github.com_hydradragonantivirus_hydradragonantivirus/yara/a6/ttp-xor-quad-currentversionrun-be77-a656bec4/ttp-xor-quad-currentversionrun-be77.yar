rule TTP_XOR_QUAD_CurrentVersionRun_be77 {
  strings:
    $key_be77 = { ed 18 [2] c9 16 [2] e2 3a [2] cc 18 [2] d8 03 [2] d7 19 [2] c9 04 [2] cb 05 [2] d0 03 [2] cc 04 [2] d0 2b }

  condition:
    any of them
}