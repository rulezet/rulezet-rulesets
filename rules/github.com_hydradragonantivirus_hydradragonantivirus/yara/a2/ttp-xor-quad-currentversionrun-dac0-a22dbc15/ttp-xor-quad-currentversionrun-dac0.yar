rule TTP_XOR_QUAD_CurrentVersionRun_dac0 {
  strings:
    $key_dac0 = { 89 af [2] ad a1 [2] 86 8d [2] a8 af [2] bc b4 [2] b3 ae [2] ad b3 [2] af b2 [2] b4 b4 [2] a8 b3 [2] b4 9c }

  condition:
    any of them
}