rule TTP_XOR_QUAD_CurrentVersionRun_da5d {
  strings:
    $key_da5d = { 89 32 [2] ad 3c [2] 86 10 [2] a8 32 [2] bc 29 [2] b3 33 [2] ad 2e [2] af 2f [2] b4 29 [2] a8 2e [2] b4 01 }

  condition:
    any of them
}