rule TTP_XOR_QUAD_CurrentVersionRun_c967 {
  strings:
    $key_c967 = { 9a 08 [2] be 06 [2] 95 2a [2] bb 08 [2] af 13 [2] a0 09 [2] be 14 [2] bc 15 [2] a7 13 [2] bb 14 [2] a7 3b }

  condition:
    any of them
}