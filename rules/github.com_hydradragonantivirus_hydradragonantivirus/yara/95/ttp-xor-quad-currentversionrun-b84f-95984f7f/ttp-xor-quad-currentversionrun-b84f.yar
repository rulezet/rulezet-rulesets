rule TTP_XOR_QUAD_CurrentVersionRun_b84f {
  strings:
    $key_b84f = { eb 20 [2] cf 2e [2] e4 02 [2] ca 20 [2] de 3b [2] d1 21 [2] cf 3c [2] cd 3d [2] d6 3b [2] ca 3c [2] d6 13 }

  condition:
    any of them
}