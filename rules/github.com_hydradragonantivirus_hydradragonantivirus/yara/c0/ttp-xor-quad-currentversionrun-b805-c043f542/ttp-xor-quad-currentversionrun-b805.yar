rule TTP_XOR_QUAD_CurrentVersionRun_b805 {
  strings:
    $key_b805 = { eb 6a [2] cf 64 [2] e4 48 [2] ca 6a [2] de 71 [2] d1 6b [2] cf 76 [2] cd 77 [2] d6 71 [2] ca 76 [2] d6 59 }

  condition:
    any of them
}