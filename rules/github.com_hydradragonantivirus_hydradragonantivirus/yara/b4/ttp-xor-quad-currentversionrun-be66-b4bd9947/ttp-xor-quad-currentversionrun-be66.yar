rule TTP_XOR_QUAD_CurrentVersionRun_be66 {
  strings:
    $key_be66 = { ed 09 [2] c9 07 [2] e2 2b [2] cc 09 [2] d8 12 [2] d7 08 [2] c9 15 [2] cb 14 [2] d0 12 [2] cc 15 [2] d0 3a }

  condition:
    any of them
}