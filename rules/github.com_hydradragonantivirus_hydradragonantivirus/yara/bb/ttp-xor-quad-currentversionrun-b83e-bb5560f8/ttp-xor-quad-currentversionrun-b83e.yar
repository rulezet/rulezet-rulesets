rule TTP_XOR_QUAD_CurrentVersionRun_b83e {
  strings:
    $key_b83e = { eb 51 [2] cf 5f [2] e4 73 [2] ca 51 [2] de 4a [2] d1 50 [2] cf 4d [2] cd 4c [2] d6 4a [2] ca 4d [2] d6 62 }

  condition:
    any of them
}