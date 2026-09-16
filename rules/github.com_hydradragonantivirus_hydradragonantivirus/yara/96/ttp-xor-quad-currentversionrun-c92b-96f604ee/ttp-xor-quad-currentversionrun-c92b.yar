rule TTP_XOR_QUAD_CurrentVersionRun_c92b {
  strings:
    $key_c92b = { 9a 44 [2] be 4a [2] 95 66 [2] bb 44 [2] af 5f [2] a0 45 [2] be 58 [2] bc 59 [2] a7 5f [2] bb 58 [2] a7 77 }

  condition:
    any of them
}