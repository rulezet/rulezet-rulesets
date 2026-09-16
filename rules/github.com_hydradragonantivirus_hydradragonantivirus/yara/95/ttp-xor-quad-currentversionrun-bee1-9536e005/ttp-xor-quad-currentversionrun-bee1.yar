rule TTP_XOR_QUAD_CurrentVersionRun_bee1 {
  strings:
    $key_bee1 = { ed 8e [2] c9 80 [2] e2 ac [2] cc 8e [2] d8 95 [2] d7 8f [2] c9 92 [2] cb 93 [2] d0 95 [2] cc 92 [2] d0 bd }

  condition:
    any of them
}