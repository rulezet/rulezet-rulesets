rule TTP_XOR_QUAD_CurrentVersionRun_a236 {
  strings:
    $key_a236 = { f1 59 [2] d5 57 [2] fe 7b [2] d0 59 [2] c4 42 [2] cb 58 [2] d5 45 [2] d7 44 [2] cc 42 [2] d0 45 [2] cc 6a }

  condition:
    any of them
}