rule TTP_XOR_QUAD_CurrentVersionRun_b87b {
  strings:
    $key_b87b = { eb 14 [2] cf 1a [2] e4 36 [2] ca 14 [2] de 0f [2] d1 15 [2] cf 08 [2] cd 09 [2] d6 0f [2] ca 08 [2] d6 27 }

  condition:
    any of them
}