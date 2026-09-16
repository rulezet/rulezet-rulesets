rule TTP_XOR_QUAD_CurrentVersionRun_a2e6 {
  strings:
    $key_a2e6 = { f1 89 [2] d5 87 [2] fe ab [2] d0 89 [2] c4 92 [2] cb 88 [2] d5 95 [2] d7 94 [2] cc 92 [2] d0 95 [2] cc ba }

  condition:
    any of them
}