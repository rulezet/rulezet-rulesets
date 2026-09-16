rule TTP_XOR_QUAD_CurrentVersionRun_da1c {
  strings:
    $key_da1c = { 89 73 [2] ad 7d [2] 86 51 [2] a8 73 [2] bc 68 [2] b3 72 [2] ad 6f [2] af 6e [2] b4 68 [2] a8 6f [2] b4 40 }

  condition:
    any of them
}