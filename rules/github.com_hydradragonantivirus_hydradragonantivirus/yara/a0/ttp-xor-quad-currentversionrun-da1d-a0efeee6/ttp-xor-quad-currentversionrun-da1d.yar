rule TTP_XOR_QUAD_CurrentVersionRun_da1d {
  strings:
    $key_da1d = { 89 72 [2] ad 7c [2] 86 50 [2] a8 72 [2] bc 69 [2] b3 73 [2] ad 6e [2] af 6f [2] b4 69 [2] a8 6e [2] b4 41 }

  condition:
    any of them
}