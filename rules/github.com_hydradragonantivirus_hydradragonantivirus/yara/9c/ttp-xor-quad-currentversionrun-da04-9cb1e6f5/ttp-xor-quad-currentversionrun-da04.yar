rule TTP_XOR_QUAD_CurrentVersionRun_da04 {
  strings:
    $key_da04 = { 89 6b [2] ad 65 [2] 86 49 [2] a8 6b [2] bc 70 [2] b3 6a [2] ad 77 [2] af 76 [2] b4 70 [2] a8 77 [2] b4 58 }

  condition:
    any of them
}