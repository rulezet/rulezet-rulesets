rule TTP_XOR_QUAD_CurrentVersionRun_b844 {
  strings:
    $key_b844 = { eb 2b [2] cf 25 [2] e4 09 [2] ca 2b [2] de 30 [2] d1 2a [2] cf 37 [2] cd 36 [2] d6 30 [2] ca 37 [2] d6 18 }

  condition:
    any of them
}