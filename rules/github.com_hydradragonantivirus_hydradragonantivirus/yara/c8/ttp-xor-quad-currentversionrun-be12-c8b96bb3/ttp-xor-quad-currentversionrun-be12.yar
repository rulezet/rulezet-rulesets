rule TTP_XOR_QUAD_CurrentVersionRun_be12 {
  strings:
    $key_be12 = { ed 7d [2] c9 73 [2] e2 5f [2] cc 7d [2] d8 66 [2] d7 7c [2] c9 61 [2] cb 60 [2] d0 66 [2] cc 61 [2] d0 4e }

  condition:
    any of them
}