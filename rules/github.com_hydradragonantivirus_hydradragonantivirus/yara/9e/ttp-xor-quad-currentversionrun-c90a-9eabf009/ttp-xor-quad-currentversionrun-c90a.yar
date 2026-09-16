rule TTP_XOR_QUAD_CurrentVersionRun_c90a {
  strings:
    $key_c90a = { 9a 65 [2] be 6b [2] 95 47 [2] bb 65 [2] af 7e [2] a0 64 [2] be 79 [2] bc 78 [2] a7 7e [2] bb 79 [2] a7 56 }

  condition:
    any of them
}