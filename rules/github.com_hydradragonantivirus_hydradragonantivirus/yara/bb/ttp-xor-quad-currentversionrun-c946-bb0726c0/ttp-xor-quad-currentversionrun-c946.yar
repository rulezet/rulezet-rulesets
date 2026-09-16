rule TTP_XOR_QUAD_CurrentVersionRun_c946 {
  strings:
    $key_c946 = { 9a 29 [2] be 27 [2] 95 0b [2] bb 29 [2] af 32 [2] a0 28 [2] be 35 [2] bc 34 [2] a7 32 [2] bb 35 [2] a7 1a }

  condition:
    any of them
}