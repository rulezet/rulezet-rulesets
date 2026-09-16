rule TTP_XOR_QUAD_CurrentVersionRun_b879 {
  strings:
    $key_b879 = { eb 16 [2] cf 18 [2] e4 34 [2] ca 16 [2] de 0d [2] d1 17 [2] cf 0a [2] cd 0b [2] d6 0d [2] ca 0a [2] d6 25 }

  condition:
    any of them
}