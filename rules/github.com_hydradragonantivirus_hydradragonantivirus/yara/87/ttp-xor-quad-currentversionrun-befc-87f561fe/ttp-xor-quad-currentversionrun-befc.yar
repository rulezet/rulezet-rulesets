rule TTP_XOR_QUAD_CurrentVersionRun_befc {
  strings:
    $key_befc = { ed 93 [2] c9 9d [2] e2 b1 [2] cc 93 [2] d8 88 [2] d7 92 [2] c9 8f [2] cb 8e [2] d0 88 [2] cc 8f [2] d0 a0 }

  condition:
    any of them
}