rule TTP_XOR_QUAD_CurrentVersionRun_befd {
  strings:
    $key_befd = { ed 92 [2] c9 9c [2] e2 b0 [2] cc 92 [2] d8 89 [2] d7 93 [2] c9 8e [2] cb 8f [2] d0 89 [2] cc 8e [2] d0 a1 }

  condition:
    any of them
}