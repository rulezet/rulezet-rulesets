rule TTP_XOR_QUAD_CurrentVersionRun_b820 {
  strings:
    $key_b820 = { eb 4f [2] cf 41 [2] e4 6d [2] ca 4f [2] de 54 [2] d1 4e [2] cf 53 [2] cd 52 [2] d6 54 [2] ca 53 [2] d6 7c }

  condition:
    any of them
}