rule TTP_XOR_QUAD_CurrentVersionRun_c96b {
  strings:
    $key_c96b = { 9a 04 [2] be 0a [2] 95 26 [2] bb 04 [2] af 1f [2] a0 05 [2] be 18 [2] bc 19 [2] a7 1f [2] bb 18 [2] a7 37 }

  condition:
    any of them
}