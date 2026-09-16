rule TTP_XOR_QUAD_CurrentVersionRun_beee {
  strings:
    $key_beee = { ed 81 [2] c9 8f [2] e2 a3 [2] cc 81 [2] d8 9a [2] d7 80 [2] c9 9d [2] cb 9c [2] d0 9a [2] cc 9d [2] d0 b2 }

  condition:
    any of them
}