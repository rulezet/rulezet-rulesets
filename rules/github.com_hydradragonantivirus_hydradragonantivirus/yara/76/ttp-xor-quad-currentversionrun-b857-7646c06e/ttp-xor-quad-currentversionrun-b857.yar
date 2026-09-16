rule TTP_XOR_QUAD_CurrentVersionRun_b857 {
  strings:
    $key_b857 = { eb 38 [2] cf 36 [2] e4 1a [2] ca 38 [2] de 23 [2] d1 39 [2] cf 24 [2] cd 25 [2] d6 23 [2] ca 24 [2] d6 0b }

  condition:
    any of them
}