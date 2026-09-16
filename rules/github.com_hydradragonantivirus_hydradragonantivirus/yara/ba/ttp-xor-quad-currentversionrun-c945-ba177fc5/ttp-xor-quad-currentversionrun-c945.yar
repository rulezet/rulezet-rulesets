rule TTP_XOR_QUAD_CurrentVersionRun_c945 {
  strings:
    $key_c945 = { 9a 2a [2] be 24 [2] 95 08 [2] bb 2a [2] af 31 [2] a0 2b [2] be 36 [2] bc 37 [2] a7 31 [2] bb 36 [2] a7 19 }

  condition:
    any of them
}