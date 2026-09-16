rule TTP_XOR_QUAD_CurrentVersionRun_da7c {
  strings:
    $key_da7c = { 89 13 [2] ad 1d [2] 86 31 [2] a8 13 [2] bc 08 [2] b3 12 [2] ad 0f [2] af 0e [2] b4 08 [2] a8 0f [2] b4 20 }

  condition:
    any of them
}