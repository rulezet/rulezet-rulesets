rule TTP_XOR_QUAD_CurrentVersionRun_c92a {
  strings:
    $key_c92a = { 9a 45 [2] be 4b [2] 95 67 [2] bb 45 [2] af 5e [2] a0 44 [2] be 59 [2] bc 58 [2] a7 5e [2] bb 59 [2] a7 76 }

  condition:
    any of them
}