rule TTP_XOR_QUAD_CurrentVersionRun_b8e8 {
  strings:
    $key_b8e8 = { eb 87 [2] cf 89 [2] e4 a5 [2] ca 87 [2] de 9c [2] d1 86 [2] cf 9b [2] cd 9a [2] d6 9c [2] ca 9b [2] d6 b4 }

  condition:
    any of them
}