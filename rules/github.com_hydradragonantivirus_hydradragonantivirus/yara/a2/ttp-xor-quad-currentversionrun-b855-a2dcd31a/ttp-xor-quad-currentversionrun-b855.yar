rule TTP_XOR_QUAD_CurrentVersionRun_b855 {
  strings:
    $key_b855 = { eb 3a [2] cf 34 [2] e4 18 [2] ca 3a [2] de 21 [2] d1 3b [2] cf 26 [2] cd 27 [2] d6 21 [2] ca 26 [2] d6 09 }

  condition:
    any of them
}