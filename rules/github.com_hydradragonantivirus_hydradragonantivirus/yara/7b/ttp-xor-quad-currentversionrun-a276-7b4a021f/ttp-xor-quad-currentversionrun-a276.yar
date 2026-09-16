rule TTP_XOR_QUAD_CurrentVersionRun_a276 {
  strings:
    $key_a276 = { f1 19 [2] d5 17 [2] fe 3b [2] d0 19 [2] c4 02 [2] cb 18 [2] d5 05 [2] d7 04 [2] cc 02 [2] d0 05 [2] cc 2a }

  condition:
    any of them
}