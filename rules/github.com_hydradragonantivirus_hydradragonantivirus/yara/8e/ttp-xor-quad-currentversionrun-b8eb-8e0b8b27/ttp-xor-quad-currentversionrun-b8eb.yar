rule TTP_XOR_QUAD_CurrentVersionRun_b8eb {
  strings:
    $key_b8eb = { eb 84 [2] cf 8a [2] e4 a6 [2] ca 84 [2] de 9f [2] d1 85 [2] cf 98 [2] cd 99 [2] d6 9f [2] ca 98 [2] d6 b7 }

  condition:
    any of them
}