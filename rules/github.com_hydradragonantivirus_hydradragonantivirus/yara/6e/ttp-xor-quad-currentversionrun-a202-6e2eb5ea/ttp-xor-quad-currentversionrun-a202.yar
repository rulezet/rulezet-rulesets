rule TTP_XOR_QUAD_CurrentVersionRun_a202 {
  strings:
    $key_a202 = { f1 6d [2] d5 63 [2] fe 4f [2] d0 6d [2] c4 76 [2] cb 6c [2] d5 71 [2] d7 70 [2] cc 76 [2] d0 71 [2] cc 5e }

  condition:
    any of them
}