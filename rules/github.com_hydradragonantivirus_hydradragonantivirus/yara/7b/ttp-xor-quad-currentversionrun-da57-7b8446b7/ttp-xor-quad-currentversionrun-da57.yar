rule TTP_XOR_QUAD_CurrentVersionRun_da57 {
  strings:
    $key_da57 = { 89 38 [2] ad 36 [2] 86 1a [2] a8 38 [2] bc 23 [2] b3 39 [2] ad 24 [2] af 25 [2] b4 23 [2] a8 24 [2] b4 0b }

  condition:
    any of them
}