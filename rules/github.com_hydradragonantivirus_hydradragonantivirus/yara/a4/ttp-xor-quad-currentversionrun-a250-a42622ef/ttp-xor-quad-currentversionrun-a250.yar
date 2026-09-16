rule TTP_XOR_QUAD_CurrentVersionRun_a250 {
  strings:
    $key_a250 = { f1 3f [2] d5 31 [2] fe 1d [2] d0 3f [2] c4 24 [2] cb 3e [2] d5 23 [2] d7 22 [2] cc 24 [2] d0 23 [2] cc 0c }

  condition:
    any of them
}