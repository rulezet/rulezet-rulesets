rule TTP_XOR_QUAD_CurrentVersionRun_da01 {
  strings:
    $key_da01 = { 89 6e [2] ad 60 [2] 86 4c [2] a8 6e [2] bc 75 [2] b3 6f [2] ad 72 [2] af 73 [2] b4 75 [2] a8 72 [2] b4 5d }

  condition:
    any of them
}