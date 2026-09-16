rule TTP_XOR_QUAD_CurrentVersionRun_b8fb {
  strings:
    $key_b8fb = { eb 94 [2] cf 9a [2] e4 b6 [2] ca 94 [2] de 8f [2] d1 95 [2] cf 88 [2] cd 89 [2] d6 8f [2] ca 88 [2] d6 a7 }

  condition:
    any of them
}