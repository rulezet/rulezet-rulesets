rule TTP_XOR_QUAD_CurrentVersionRun_befa {
  strings:
    $key_befa = { ed 95 [2] c9 9b [2] e2 b7 [2] cc 95 [2] d8 8e [2] d7 94 [2] c9 89 [2] cb 88 [2] d0 8e [2] cc 89 [2] d0 a6 }

  condition:
    any of them
}