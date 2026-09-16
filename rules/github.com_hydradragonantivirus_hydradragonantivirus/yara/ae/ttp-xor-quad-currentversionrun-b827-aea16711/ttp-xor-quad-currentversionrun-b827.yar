rule TTP_XOR_QUAD_CurrentVersionRun_b827 {
  strings:
    $key_b827 = { eb 48 [2] cf 46 [2] e4 6a [2] ca 48 [2] de 53 [2] d1 49 [2] cf 54 [2] cd 55 [2] d6 53 [2] ca 54 [2] d6 7b }

  condition:
    any of them
}