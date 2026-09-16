rule TTP_XOR_QUAD_CurrentVersionRun_a27a {
  strings:
    $key_a27a = { f1 15 [2] d5 1b [2] fe 37 [2] d0 15 [2] c4 0e [2] cb 14 [2] d5 09 [2] d7 08 [2] cc 0e [2] d0 09 [2] cc 26 }

  condition:
    any of them
}