rule TTP_XOR_QUAD_CurrentVersionRun_b806 {
  strings:
    $key_b806 = { eb 69 [2] cf 67 [2] e4 4b [2] ca 69 [2] de 72 [2] d1 68 [2] cf 75 [2] cd 74 [2] d6 72 [2] ca 75 [2] d6 5a }

  condition:
    any of them
}