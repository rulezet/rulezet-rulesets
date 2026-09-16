rule TTP_XOR_QUAD_CurrentVersionRun_b8f5 {
  strings:
    $key_b8f5 = { eb 9a [2] cf 94 [2] e4 b8 [2] ca 9a [2] de 81 [2] d1 9b [2] cf 86 [2] cd 87 [2] d6 81 [2] ca 86 [2] d6 a9 }

  condition:
    any of them
}