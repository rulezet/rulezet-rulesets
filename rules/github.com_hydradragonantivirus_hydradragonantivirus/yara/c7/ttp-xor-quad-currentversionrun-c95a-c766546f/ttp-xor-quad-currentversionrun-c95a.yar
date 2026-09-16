rule TTP_XOR_QUAD_CurrentVersionRun_c95a {
  strings:
    $key_c95a = { 9a 35 [2] be 3b [2] 95 17 [2] bb 35 [2] af 2e [2] a0 34 [2] be 29 [2] bc 28 [2] a7 2e [2] bb 29 [2] a7 06 }

  condition:
    any of them
}