rule TTP_XOR_QUAD_CurrentVersionRun_da59 {
  strings:
    $key_da59 = { 89 36 [2] ad 38 [2] 86 14 [2] a8 36 [2] bc 2d [2] b3 37 [2] ad 2a [2] af 2b [2] b4 2d [2] a8 2a [2] b4 05 }

  condition:
    any of them
}