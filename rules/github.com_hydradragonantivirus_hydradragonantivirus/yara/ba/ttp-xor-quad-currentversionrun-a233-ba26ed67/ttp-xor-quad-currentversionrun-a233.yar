rule TTP_XOR_QUAD_CurrentVersionRun_a233 {
  strings:
    $key_a233 = { f1 5c [2] d5 52 [2] fe 7e [2] d0 5c [2] c4 47 [2] cb 5d [2] d5 40 [2] d7 41 [2] cc 47 [2] d0 40 [2] cc 6f }

  condition:
    any of them
}