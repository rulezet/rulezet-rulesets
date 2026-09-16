rule TTP_XOR_QUAD_CurrentVersionRun_a5ec {
  strings:
    $key_a5ec = { f6 83 [2] d2 8d [2] f9 a1 [2] d7 83 [2] c3 98 [2] cc 82 [2] d2 9f [2] d0 9e [2] cb 98 [2] d7 9f [2] cb b0 }

  condition:
    any of them
}