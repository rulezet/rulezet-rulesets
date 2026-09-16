rule TTP_XOR_QUAD_CurrentVersionRun_c947 {
  strings:
    $key_c947 = { 9a 28 [2] be 26 [2] 95 0a [2] bb 28 [2] af 33 [2] a0 29 [2] be 34 [2] bc 35 [2] a7 33 [2] bb 34 [2] a7 1b }

  condition:
    any of them
}