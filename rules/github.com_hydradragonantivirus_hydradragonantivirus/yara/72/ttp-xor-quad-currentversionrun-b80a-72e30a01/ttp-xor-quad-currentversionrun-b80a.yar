rule TTP_XOR_QUAD_CurrentVersionRun_b80a {
  strings:
    $key_b80a = { eb 65 [2] cf 6b [2] e4 47 [2] ca 65 [2] de 7e [2] d1 64 [2] cf 79 [2] cd 78 [2] d6 7e [2] ca 79 [2] d6 56 }

  condition:
    any of them
}