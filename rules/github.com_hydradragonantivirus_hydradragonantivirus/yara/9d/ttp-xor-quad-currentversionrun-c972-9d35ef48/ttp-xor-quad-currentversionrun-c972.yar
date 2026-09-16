rule TTP_XOR_QUAD_CurrentVersionRun_c972 {
  strings:
    $key_c972 = { 9a 1d [2] be 13 [2] 95 3f [2] bb 1d [2] af 06 [2] a0 1c [2] be 01 [2] bc 00 [2] a7 06 [2] bb 01 [2] a7 2e }

  condition:
    any of them
}