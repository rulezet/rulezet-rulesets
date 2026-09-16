rule TTP_XOR_QUAD_CurrentVersionRun_b86a {
  strings:
    $key_b86a = { eb 05 [2] cf 0b [2] e4 27 [2] ca 05 [2] de 1e [2] d1 04 [2] cf 19 [2] cd 18 [2] d6 1e [2] ca 19 [2] d6 36 }

  condition:
    any of them
}