rule TTP_XOR_QUAD_CurrentVersionRun_da0d {
  strings:
    $key_da0d = { 89 62 [2] ad 6c [2] 86 40 [2] a8 62 [2] bc 79 [2] b3 63 [2] ad 7e [2] af 7f [2] b4 79 [2] a8 7e [2] b4 51 }

  condition:
    any of them
}