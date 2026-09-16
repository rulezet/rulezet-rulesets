rule TTP_XOR_QUAD_CurrentVersionRun_b80e {
  strings:
    $key_b80e = { eb 61 [2] cf 6f [2] e4 43 [2] ca 61 [2] de 7a [2] d1 60 [2] cf 7d [2] cd 7c [2] d6 7a [2] ca 7d [2] d6 52 }

  condition:
    any of them
}