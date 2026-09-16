rule TTP_XOR_QUAD_CurrentVersionRun_b8f9 {
  strings:
    $key_b8f9 = { eb 96 [2] cf 98 [2] e4 b4 [2] ca 96 [2] de 8d [2] d1 97 [2] cf 8a [2] cd 8b [2] d6 8d [2] ca 8a [2] d6 a5 }

  condition:
    any of them
}