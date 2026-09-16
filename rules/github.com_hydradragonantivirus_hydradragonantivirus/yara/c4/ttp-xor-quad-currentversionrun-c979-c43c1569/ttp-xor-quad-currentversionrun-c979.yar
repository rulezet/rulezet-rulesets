rule TTP_XOR_QUAD_CurrentVersionRun_c979 {
  strings:
    $key_c979 = { 9a 16 [2] be 18 [2] 95 34 [2] bb 16 [2] af 0d [2] a0 17 [2] be 0a [2] bc 0b [2] a7 0d [2] bb 0a [2] a7 25 }

  condition:
    any of them
}