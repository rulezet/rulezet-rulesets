rule TTP_XOR_QUAD_CurrentVersionRun_c971 {
  strings:
    $key_c971 = { 9a 1e [2] be 10 [2] 95 3c [2] bb 1e [2] af 05 [2] a0 1f [2] be 02 [2] bc 03 [2] a7 05 [2] bb 02 [2] a7 2d }

  condition:
    any of them
}