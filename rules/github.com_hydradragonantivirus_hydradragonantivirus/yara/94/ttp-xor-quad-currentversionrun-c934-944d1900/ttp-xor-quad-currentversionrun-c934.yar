rule TTP_XOR_QUAD_CurrentVersionRun_c934 {
  strings:
    $key_c934 = { 9a 5b [2] be 55 [2] 95 79 [2] bb 5b [2] af 40 [2] a0 5a [2] be 47 [2] bc 46 [2] a7 40 [2] bb 47 [2] a7 68 }

  condition:
    any of them
}