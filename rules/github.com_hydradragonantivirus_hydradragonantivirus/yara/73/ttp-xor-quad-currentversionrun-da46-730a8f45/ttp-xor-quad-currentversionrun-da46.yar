rule TTP_XOR_QUAD_CurrentVersionRun_da46 {
  strings:
    $key_da46 = { 89 29 [2] ad 27 [2] 86 0b [2] a8 29 [2] bc 32 [2] b3 28 [2] ad 35 [2] af 34 [2] b4 32 [2] a8 35 [2] b4 1a }

  condition:
    any of them
}