rule TTP_XOR_QUAD_CurrentVersionRun_b864 {
  strings:
    $key_b864 = { eb 0b [2] cf 05 [2] e4 29 [2] ca 0b [2] de 10 [2] d1 0a [2] cf 17 [2] cd 16 [2] d6 10 [2] ca 17 [2] d6 38 }

  condition:
    any of them
}