rule TTP_XOR_QUAD_CurrentVersionRun_da65 {
  strings:
    $key_da65 = { 89 0a [2] ad 04 [2] 86 28 [2] a8 0a [2] bc 11 [2] b3 0b [2] ad 16 [2] af 17 [2] b4 11 [2] a8 16 [2] b4 39 }

  condition:
    any of them
}