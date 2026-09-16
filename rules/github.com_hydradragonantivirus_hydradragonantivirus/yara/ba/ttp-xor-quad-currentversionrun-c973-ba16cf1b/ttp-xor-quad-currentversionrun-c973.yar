rule TTP_XOR_QUAD_CurrentVersionRun_c973 {
  strings:
    $key_c973 = { 9a 1c [2] be 12 [2] 95 3e [2] bb 1c [2] af 07 [2] a0 1d [2] be 00 [2] bc 01 [2] a7 07 [2] bb 00 [2] a7 2f }

  condition:
    any of them
}