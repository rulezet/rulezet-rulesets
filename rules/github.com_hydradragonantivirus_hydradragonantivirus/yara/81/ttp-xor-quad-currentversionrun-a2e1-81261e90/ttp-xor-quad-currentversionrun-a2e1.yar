rule TTP_XOR_QUAD_CurrentVersionRun_a2e1 {
  strings:
    $key_a2e1 = { f1 8e [2] d5 80 [2] fe ac [2] d0 8e [2] c4 95 [2] cb 8f [2] d5 92 [2] d7 93 [2] cc 95 [2] d0 92 [2] cc bd }

  condition:
    any of them
}