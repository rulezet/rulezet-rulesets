rule TTP_XOR_QUAD_CurrentVersionRun_c944 {
  strings:
    $key_c944 = { 9a 2b [2] be 25 [2] 95 09 [2] bb 2b [2] af 30 [2] a0 2a [2] be 37 [2] bc 36 [2] a7 30 [2] bb 37 [2] a7 18 }

  condition:
    any of them
}