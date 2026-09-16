rule TTP_XOR_QUAD_CurrentVersionRun_da69 {
  strings:
    $key_da69 = { 89 06 [2] ad 08 [2] 86 24 [2] a8 06 [2] bc 1d [2] b3 07 [2] ad 1a [2] af 1b [2] b4 1d [2] a8 1a [2] b4 35 }

  condition:
    any of them
}