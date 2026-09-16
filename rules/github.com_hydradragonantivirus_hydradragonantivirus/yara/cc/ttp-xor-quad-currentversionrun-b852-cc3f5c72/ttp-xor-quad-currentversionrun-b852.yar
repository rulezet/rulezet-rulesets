rule TTP_XOR_QUAD_CurrentVersionRun_b852 {
  strings:
    $key_b852 = { eb 3d [2] cf 33 [2] e4 1f [2] ca 3d [2] de 26 [2] d1 3c [2] cf 21 [2] cd 20 [2] d6 26 [2] ca 21 [2] d6 0e }

  condition:
    any of them
}