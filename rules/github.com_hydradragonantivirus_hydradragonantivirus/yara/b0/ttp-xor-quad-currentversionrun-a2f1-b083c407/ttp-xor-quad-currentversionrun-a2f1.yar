rule TTP_XOR_QUAD_CurrentVersionRun_a2f1 {
  strings:
    $key_a2f1 = { f1 9e [2] d5 90 [2] fe bc [2] d0 9e [2] c4 85 [2] cb 9f [2] d5 82 [2] d7 83 [2] cc 85 [2] d0 82 [2] cc ad }

  condition:
    any of them
}