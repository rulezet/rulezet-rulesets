rule TTP_XOR_QUAD_CurrentVersionRun_da15 {
  strings:
    $key_da15 = { 89 7a [2] ad 74 [2] 86 58 [2] a8 7a [2] bc 61 [2] b3 7b [2] ad 66 [2] af 67 [2] b4 61 [2] a8 66 [2] b4 49 }

  condition:
    any of them
}