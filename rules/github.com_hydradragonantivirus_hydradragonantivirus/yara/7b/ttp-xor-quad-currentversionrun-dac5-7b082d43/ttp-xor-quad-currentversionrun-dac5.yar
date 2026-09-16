rule TTP_XOR_QUAD_CurrentVersionRun_dac5 {
  strings:
    $key_dac5 = { 89 aa [2] ad a4 [2] 86 88 [2] a8 aa [2] bc b1 [2] b3 ab [2] ad b6 [2] af b7 [2] b4 b1 [2] a8 b6 [2] b4 99 }

  condition:
    any of them
}