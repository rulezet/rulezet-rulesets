rule TTP_XOR_QUAD_CurrentVersionRun_b835 {
  strings:
    $key_b835 = { eb 5a [2] cf 54 [2] e4 78 [2] ca 5a [2] de 41 [2] d1 5b [2] cf 46 [2] cd 47 [2] d6 41 [2] ca 46 [2] d6 69 }

  condition:
    any of them
}