rule TTP_XOR_QUAD_CurrentVersionRun_da68 {
  strings:
    $key_da68 = { 89 07 [2] ad 09 [2] 86 25 [2] a8 07 [2] bc 1c [2] b3 06 [2] ad 1b [2] af 1a [2] b4 1c [2] a8 1b [2] b4 34 }

  condition:
    any of them
}