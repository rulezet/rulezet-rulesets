rule TTP_XOR_QUAD_CurrentVersionRun_beed {
  strings:
    $key_beed = { ed 82 [2] c9 8c [2] e2 a0 [2] cc 82 [2] d8 99 [2] d7 83 [2] c9 9e [2] cb 9f [2] d0 99 [2] cc 9e [2] d0 b1 }

  condition:
    any of them
}