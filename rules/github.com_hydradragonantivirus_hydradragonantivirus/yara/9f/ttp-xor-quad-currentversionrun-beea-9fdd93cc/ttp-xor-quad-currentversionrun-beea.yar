rule TTP_XOR_QUAD_CurrentVersionRun_beea {
  strings:
    $key_beea = { ed 85 [2] c9 8b [2] e2 a7 [2] cc 85 [2] d8 9e [2] d7 84 [2] c9 99 [2] cb 98 [2] d0 9e [2] cc 99 [2] d0 b6 }

  condition:
    any of them
}