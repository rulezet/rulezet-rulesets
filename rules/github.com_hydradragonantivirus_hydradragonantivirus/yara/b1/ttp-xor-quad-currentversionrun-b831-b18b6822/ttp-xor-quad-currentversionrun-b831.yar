rule TTP_XOR_QUAD_CurrentVersionRun_b831 {
  strings:
    $key_b831 = { eb 5e [2] cf 50 [2] e4 7c [2] ca 5e [2] de 45 [2] d1 5f [2] cf 42 [2] cd 43 [2] d6 45 [2] ca 42 [2] d6 6d }

  condition:
    any of them
}