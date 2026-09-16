rule TTP_XOR_QUAD_CurrentVersionRun_c954 {
  strings:
    $key_c954 = { 9a 3b [2] be 35 [2] 95 19 [2] bb 3b [2] af 20 [2] a0 3a [2] be 27 [2] bc 26 [2] a7 20 [2] bb 27 [2] a7 08 }

  condition:
    any of them
}