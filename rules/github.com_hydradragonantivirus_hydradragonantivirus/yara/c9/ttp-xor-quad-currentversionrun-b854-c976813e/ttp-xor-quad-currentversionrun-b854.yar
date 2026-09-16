rule TTP_XOR_QUAD_CurrentVersionRun_b854 {
  strings:
    $key_b854 = { eb 3b [2] cf 35 [2] e4 19 [2] ca 3b [2] de 20 [2] d1 3a [2] cf 27 [2] cd 26 [2] d6 20 [2] ca 27 [2] d6 08 }

  condition:
    any of them
}