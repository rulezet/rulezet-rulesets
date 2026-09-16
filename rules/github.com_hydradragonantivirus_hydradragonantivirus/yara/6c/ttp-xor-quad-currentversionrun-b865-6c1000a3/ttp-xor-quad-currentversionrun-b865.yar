rule TTP_XOR_QUAD_CurrentVersionRun_b865 {
  strings:
    $key_b865 = { eb 0a [2] cf 04 [2] e4 28 [2] ca 0a [2] de 11 [2] d1 0b [2] cf 16 [2] cd 17 [2] d6 11 [2] ca 16 [2] d6 39 }

  condition:
    any of them
}