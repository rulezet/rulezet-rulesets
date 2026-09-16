rule TTP_XOR_QUAD_CurrentVersionRun_b82b {
  strings:
    $key_b82b = { eb 44 [2] cf 4a [2] e4 66 [2] ca 44 [2] de 5f [2] d1 45 [2] cf 58 [2] cd 59 [2] d6 5f [2] ca 58 [2] d6 77 }

  condition:
    any of them
}