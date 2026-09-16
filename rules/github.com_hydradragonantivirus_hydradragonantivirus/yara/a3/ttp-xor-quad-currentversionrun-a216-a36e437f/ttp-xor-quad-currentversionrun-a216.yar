rule TTP_XOR_QUAD_CurrentVersionRun_a216 {
  strings:
    $key_a216 = { f1 79 [2] d5 77 [2] fe 5b [2] d0 79 [2] c4 62 [2] cb 78 [2] d5 65 [2] d7 64 [2] cc 62 [2] d0 65 [2] cc 4a }

  condition:
    any of them
}