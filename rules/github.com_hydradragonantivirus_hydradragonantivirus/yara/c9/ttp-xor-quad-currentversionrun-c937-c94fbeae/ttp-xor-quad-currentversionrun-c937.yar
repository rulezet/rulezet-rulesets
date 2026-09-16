rule TTP_XOR_QUAD_CurrentVersionRun_c937 {
  strings:
    $key_c937 = { 9a 58 [2] be 56 [2] 95 7a [2] bb 58 [2] af 43 [2] a0 59 [2] be 44 [2] bc 45 [2] a7 43 [2] bb 44 [2] a7 6b }

  condition:
    any of them
}