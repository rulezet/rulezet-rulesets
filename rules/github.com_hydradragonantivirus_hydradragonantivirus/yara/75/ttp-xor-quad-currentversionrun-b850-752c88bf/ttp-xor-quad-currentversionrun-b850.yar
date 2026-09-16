rule TTP_XOR_QUAD_CurrentVersionRun_b850 {
  strings:
    $key_b850 = { eb 3f [2] cf 31 [2] e4 1d [2] ca 3f [2] de 24 [2] d1 3e [2] cf 23 [2] cd 22 [2] d6 24 [2] ca 23 [2] d6 0c }

  condition:
    any of them
}