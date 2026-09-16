rule TTP_XOR_QUAD_CurrentVersionRun_b8e5 {
  strings:
    $key_b8e5 = { eb 8a [2] cf 84 [2] e4 a8 [2] ca 8a [2] de 91 [2] d1 8b [2] cf 96 [2] cd 97 [2] d6 91 [2] ca 96 [2] d6 b9 }

  condition:
    any of them
}