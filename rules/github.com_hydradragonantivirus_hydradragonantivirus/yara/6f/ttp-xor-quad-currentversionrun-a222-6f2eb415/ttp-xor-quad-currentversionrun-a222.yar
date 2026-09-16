rule TTP_XOR_QUAD_CurrentVersionRun_a222 {
  strings:
    $key_a222 = { f1 4d [2] d5 43 [2] fe 6f [2] d0 4d [2] c4 56 [2] cb 4c [2] d5 51 [2] d7 50 [2] cc 56 [2] d0 51 [2] cc 7e }

  condition:
    any of them
}