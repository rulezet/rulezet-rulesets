rule TTP_XOR_QUAD_CurrentVersionRun_b824 {
  strings:
    $key_b824 = { eb 4b [2] cf 45 [2] e4 69 [2] ca 4b [2] de 50 [2] d1 4a [2] cf 57 [2] cd 56 [2] d6 50 [2] ca 57 [2] d6 78 }

  condition:
    any of them
}