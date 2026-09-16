rule TTP_XOR_QUAD_CurrentVersionRun_c90c {
  strings:
    $key_c90c = { 9a 63 [2] be 6d [2] 95 41 [2] bb 63 [2] af 78 [2] a0 62 [2] be 7f [2] bc 7e [2] a7 78 [2] bb 7f [2] a7 50 }

  condition:
    any of them
}