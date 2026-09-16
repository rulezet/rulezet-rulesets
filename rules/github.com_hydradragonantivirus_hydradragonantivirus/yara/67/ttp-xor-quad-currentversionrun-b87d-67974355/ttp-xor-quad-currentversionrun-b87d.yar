rule TTP_XOR_QUAD_CurrentVersionRun_b87d {
  strings:
    $key_b87d = { eb 12 [2] cf 1c [2] e4 30 [2] ca 12 [2] de 09 [2] d1 13 [2] cf 0e [2] cd 0f [2] d6 09 [2] ca 0e [2] d6 21 }

  condition:
    any of them
}