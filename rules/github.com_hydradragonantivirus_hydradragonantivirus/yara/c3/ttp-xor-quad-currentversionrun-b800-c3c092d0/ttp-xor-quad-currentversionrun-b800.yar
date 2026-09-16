rule TTP_XOR_QUAD_CurrentVersionRun_b800 {
  strings:
    $key_b800 = { eb 6f [2] cf 61 [2] e4 4d [2] ca 6f [2] de 74 [2] d1 6e [2] cf 73 [2] cd 72 [2] d6 74 [2] ca 73 [2] d6 5c }

  condition:
    any of them
}