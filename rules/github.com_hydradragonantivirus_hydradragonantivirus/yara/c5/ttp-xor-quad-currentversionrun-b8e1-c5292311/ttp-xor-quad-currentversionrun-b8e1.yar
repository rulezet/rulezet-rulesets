rule TTP_XOR_QUAD_CurrentVersionRun_b8e1 {
  strings:
    $key_b8e1 = { eb 8e [2] cf 80 [2] e4 ac [2] ca 8e [2] de 95 [2] d1 8f [2] cf 92 [2] cd 93 [2] d6 95 [2] ca 92 [2] d6 bd }

  condition:
    any of them
}