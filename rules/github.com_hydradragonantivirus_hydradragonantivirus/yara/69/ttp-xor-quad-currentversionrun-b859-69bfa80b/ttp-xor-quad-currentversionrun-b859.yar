rule TTP_XOR_QUAD_CurrentVersionRun_b859 {
  strings:
    $key_b859 = { eb 36 [2] cf 38 [2] e4 14 [2] ca 36 [2] de 2d [2] d1 37 [2] cf 2a [2] cd 2b [2] d6 2d [2] ca 2a [2] d6 05 }

  condition:
    any of them
}