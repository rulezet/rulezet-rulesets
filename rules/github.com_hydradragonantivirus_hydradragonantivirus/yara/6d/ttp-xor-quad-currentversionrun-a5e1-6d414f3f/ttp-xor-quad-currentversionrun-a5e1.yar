rule TTP_XOR_QUAD_CurrentVersionRun_a5e1 {
  strings:
    $key_a5e1 = { f6 8e [2] d2 80 [2] f9 ac [2] d7 8e [2] c3 95 [2] cc 8f [2] d2 92 [2] d0 93 [2] cb 95 [2] d7 92 [2] cb bd }

  condition:
    any of them
}