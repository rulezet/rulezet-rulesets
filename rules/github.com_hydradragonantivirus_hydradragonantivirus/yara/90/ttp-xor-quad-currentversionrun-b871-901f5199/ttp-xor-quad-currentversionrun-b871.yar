rule TTP_XOR_QUAD_CurrentVersionRun_b871 {
  strings:
    $key_b871 = { eb 1e [2] cf 10 [2] e4 3c [2] ca 1e [2] de 05 [2] d1 1f [2] cf 02 [2] cd 03 [2] d6 05 [2] ca 02 [2] d6 2d }

  condition:
    any of them
}