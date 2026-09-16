rule TTP_XOR_QUAD_CurrentVersionRun_b81a {
  strings:
    $key_b81a = { eb 75 [2] cf 7b [2] e4 57 [2] ca 75 [2] de 6e [2] d1 74 [2] cf 69 [2] cd 68 [2] d6 6e [2] ca 69 [2] d6 46 }

  condition:
    any of them
}