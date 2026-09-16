rule TTP_XOR_QUAD_CurrentVersionRun_b832 {
  strings:
    $key_b832 = { eb 5d [2] cf 53 [2] e4 7f [2] ca 5d [2] de 46 [2] d1 5c [2] cf 41 [2] cd 40 [2] d6 46 [2] ca 41 [2] d6 6e }

  condition:
    any of them
}