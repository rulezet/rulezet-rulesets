rule TTP_XOR_QUAD_CurrentVersionRun_a203 {
  strings:
    $key_a203 = { f1 6c [2] d5 62 [2] fe 4e [2] d0 6c [2] c4 77 [2] cb 6d [2] d5 70 [2] d7 71 [2] cc 77 [2] d0 70 [2] cc 5f }

  condition:
    any of them
}