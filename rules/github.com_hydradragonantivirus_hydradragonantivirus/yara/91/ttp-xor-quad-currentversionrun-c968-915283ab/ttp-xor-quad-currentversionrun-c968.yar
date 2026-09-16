rule TTP_XOR_QUAD_CurrentVersionRun_c968 {
  strings:
    $key_c968 = { 9a 07 [2] be 09 [2] 95 25 [2] bb 07 [2] af 1c [2] a0 06 [2] be 1b [2] bc 1a [2] a7 1c [2] bb 1b [2] a7 34 }

  condition:
    any of them
}