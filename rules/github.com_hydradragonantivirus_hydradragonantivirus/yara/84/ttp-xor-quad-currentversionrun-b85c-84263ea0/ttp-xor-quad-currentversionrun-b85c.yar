rule TTP_XOR_QUAD_CurrentVersionRun_b85c {
  strings:
    $key_b85c = { eb 33 [2] cf 3d [2] e4 11 [2] ca 33 [2] de 28 [2] d1 32 [2] cf 2f [2] cd 2e [2] d6 28 [2] ca 2f [2] d6 00 }

  condition:
    any of them
}