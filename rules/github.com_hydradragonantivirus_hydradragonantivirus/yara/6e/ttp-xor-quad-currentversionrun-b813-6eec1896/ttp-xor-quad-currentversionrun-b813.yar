rule TTP_XOR_QUAD_CurrentVersionRun_b813 {
  strings:
    $key_b813 = { eb 7c [2] cf 72 [2] e4 5e [2] ca 7c [2] de 67 [2] d1 7d [2] cf 60 [2] cd 61 [2] d6 67 [2] ca 60 [2] d6 4f }

  condition:
    any of them
}