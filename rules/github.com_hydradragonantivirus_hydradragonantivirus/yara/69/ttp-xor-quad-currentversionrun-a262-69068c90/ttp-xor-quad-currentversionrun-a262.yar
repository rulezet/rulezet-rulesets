rule TTP_XOR_QUAD_CurrentVersionRun_a262 {
  strings:
    $key_a262 = { f1 0d [2] d5 03 [2] fe 2f [2] d0 0d [2] c4 16 [2] cb 0c [2] d5 11 [2] d7 10 [2] cc 16 [2] d0 11 [2] cc 3e }

  condition:
    any of them
}