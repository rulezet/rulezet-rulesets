rule TTP_XOR_QUAD_CurrentVersionRun_a25a {
  strings:
    $key_a25a = { f1 35 [2] d5 3b [2] fe 17 [2] d0 35 [2] c4 2e [2] cb 34 [2] d5 29 [2] d7 28 [2] cc 2e [2] d0 29 [2] cc 06 }

  condition:
    any of them
}