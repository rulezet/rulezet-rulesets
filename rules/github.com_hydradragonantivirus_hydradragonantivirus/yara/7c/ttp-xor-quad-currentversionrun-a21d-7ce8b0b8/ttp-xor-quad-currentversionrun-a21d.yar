rule TTP_XOR_QUAD_CurrentVersionRun_a21d {
  strings:
    $key_a21d = { f1 72 [2] d5 7c [2] fe 50 [2] d0 72 [2] c4 69 [2] cb 73 [2] d5 6e [2] d7 6f [2] cc 69 [2] d0 6e [2] cc 41 }

  condition:
    any of them
}