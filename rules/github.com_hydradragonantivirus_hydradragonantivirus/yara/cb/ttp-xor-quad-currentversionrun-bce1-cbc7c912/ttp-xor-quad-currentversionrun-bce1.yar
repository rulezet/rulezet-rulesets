rule TTP_XOR_QUAD_CurrentVersionRun_bce1 {
  strings:
    $key_bce1 = { ef 8e [2] cb 80 [2] e0 ac [2] ce 8e [2] da 95 [2] d5 8f [2] cb 92 [2] c9 93 [2] d2 95 [2] ce 92 [2] d2 bd }

  condition:
    any of them
}