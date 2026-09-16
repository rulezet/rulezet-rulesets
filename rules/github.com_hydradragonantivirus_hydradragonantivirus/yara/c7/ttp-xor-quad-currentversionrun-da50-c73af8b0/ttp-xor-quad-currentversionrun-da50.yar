rule TTP_XOR_QUAD_CurrentVersionRun_da50 {
  strings:
    $key_da50 = { 89 3f [2] ad 31 [2] 86 1d [2] a8 3f [2] bc 24 [2] b3 3e [2] ad 23 [2] af 22 [2] b4 24 [2] a8 23 [2] b4 0c }

  condition:
    any of them
}