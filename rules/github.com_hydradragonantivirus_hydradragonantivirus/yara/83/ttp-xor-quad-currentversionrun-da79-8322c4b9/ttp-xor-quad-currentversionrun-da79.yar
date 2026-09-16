rule TTP_XOR_QUAD_CurrentVersionRun_da79 {
  strings:
    $key_da79 = { 89 16 [2] ad 18 [2] 86 34 [2] a8 16 [2] bc 0d [2] b3 17 [2] ad 0a [2] af 0b [2] b4 0d [2] a8 0a [2] b4 25 }

  condition:
    any of them
}