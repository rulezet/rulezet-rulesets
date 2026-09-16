rule TTP_XOR_QUAD_CurrentVersionRun_a227 {
  strings:
    $key_a227 = { f1 48 [2] d5 46 [2] fe 6a [2] d0 48 [2] c4 53 [2] cb 49 [2] d5 54 [2] d7 55 [2] cc 53 [2] d0 54 [2] cc 7b }

  condition:
    any of them
}