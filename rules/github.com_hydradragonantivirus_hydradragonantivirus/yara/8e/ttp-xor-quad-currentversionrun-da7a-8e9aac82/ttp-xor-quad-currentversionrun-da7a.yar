rule TTP_XOR_QUAD_CurrentVersionRun_da7a {
  strings:
    $key_da7a = { 89 15 [2] ad 1b [2] 86 37 [2] a8 15 [2] bc 0e [2] b3 14 [2] ad 09 [2] af 08 [2] b4 0e [2] a8 09 [2] b4 26 }

  condition:
    any of them
}