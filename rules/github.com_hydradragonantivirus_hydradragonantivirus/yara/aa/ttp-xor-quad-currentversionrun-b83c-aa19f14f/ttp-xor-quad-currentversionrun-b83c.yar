rule TTP_XOR_QUAD_CurrentVersionRun_b83c {
  strings:
    $key_b83c = { eb 53 [2] cf 5d [2] e4 71 [2] ca 53 [2] de 48 [2] d1 52 [2] cf 4f [2] cd 4e [2] d6 48 [2] ca 4f [2] d6 60 }

  condition:
    any of them
}