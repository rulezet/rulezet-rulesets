rule TTP_XOR_QUAD_CurrentVersionRun_a2e2 {
  strings:
    $key_a2e2 = { f1 8d [2] d5 83 [2] fe af [2] d0 8d [2] c4 96 [2] cb 8c [2] d5 91 [2] d7 90 [2] cc 96 [2] d0 91 [2] cc be }

  condition:
    any of them
}