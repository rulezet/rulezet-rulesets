rule TTP_XOR_QUAD_CurrentVersionRun_b83f {
  strings:
    $key_b83f = { eb 50 [2] cf 5e [2] e4 72 [2] ca 50 [2] de 4b [2] d1 51 [2] cf 4c [2] cd 4d [2] d6 4b [2] ca 4c [2] d6 63 }

  condition:
    any of them
}