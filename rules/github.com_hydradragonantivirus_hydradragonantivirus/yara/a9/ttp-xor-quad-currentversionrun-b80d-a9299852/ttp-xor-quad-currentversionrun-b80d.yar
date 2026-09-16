rule TTP_XOR_QUAD_CurrentVersionRun_b80d {
  strings:
    $key_b80d = { eb 62 [2] cf 6c [2] e4 40 [2] ca 62 [2] de 79 [2] d1 63 [2] cf 7e [2] cd 7f [2] d6 79 [2] ca 7e [2] d6 51 }

  condition:
    any of them
}