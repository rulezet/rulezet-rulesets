rule TTP_XOR_QUAD_CurrentVersionRun_b84b {
  strings:
    $key_b84b = { eb 24 [2] cf 2a [2] e4 06 [2] ca 24 [2] de 3f [2] d1 25 [2] cf 38 [2] cd 39 [2] d6 3f [2] ca 38 [2] d6 17 }

  condition:
    any of them
}