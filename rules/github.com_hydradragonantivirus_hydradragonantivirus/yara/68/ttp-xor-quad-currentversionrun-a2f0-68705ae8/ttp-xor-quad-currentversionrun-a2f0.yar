rule TTP_XOR_QUAD_CurrentVersionRun_a2f0 {
  strings:
    $key_a2f0 = { f1 9f [2] d5 91 [2] fe bd [2] d0 9f [2] c4 84 [2] cb 9e [2] d5 83 [2] d7 82 [2] cc 84 [2] d0 83 [2] cc ac }

  condition:
    any of them
}