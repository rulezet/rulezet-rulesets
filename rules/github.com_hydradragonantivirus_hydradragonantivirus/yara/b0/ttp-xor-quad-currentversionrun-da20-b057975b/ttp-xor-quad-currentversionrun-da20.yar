rule TTP_XOR_QUAD_CurrentVersionRun_da20 {
  strings:
    $key_da20 = { 89 4f [2] ad 41 [2] 86 6d [2] a8 4f [2] bc 54 [2] b3 4e [2] ad 53 [2] af 52 [2] b4 54 [2] a8 53 [2] b4 7c }

  condition:
    any of them
}