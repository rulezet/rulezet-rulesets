rule TTP_XOR_QUAD_CurrentVersionRun_c9e5 {
  strings:
    $key_c9e5 = { 9a 8a [2] be 84 [2] 95 a8 [2] bb 8a [2] af 91 [2] a0 8b [2] be 96 [2] bc 97 [2] a7 91 [2] bb 96 [2] a7 b9 }

  condition:
    any of them
}