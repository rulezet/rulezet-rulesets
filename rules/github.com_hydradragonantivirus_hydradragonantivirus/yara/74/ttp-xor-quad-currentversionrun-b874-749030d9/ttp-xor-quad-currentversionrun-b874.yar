rule TTP_XOR_QUAD_CurrentVersionRun_b874 {
  strings:
    $key_b874 = { eb 1b [2] cf 15 [2] e4 39 [2] ca 1b [2] de 00 [2] d1 1a [2] cf 07 [2] cd 06 [2] d6 00 [2] ca 07 [2] d6 28 }

  condition:
    any of them
}