rule TTP_XOR_QUAD_CurrentVersionRun_b830 {
  strings:
    $key_b830 = { eb 5f [2] cf 51 [2] e4 7d [2] ca 5f [2] de 44 [2] d1 5e [2] cf 43 [2] cd 42 [2] d6 44 [2] ca 43 [2] d6 6c }

  condition:
    any of them
}