rule TTP_XOR_QUAD_CurrentVersionRun_c925 {
  strings:
    $key_c925 = { 9a 4a [2] be 44 [2] 95 68 [2] bb 4a [2] af 51 [2] a0 4b [2] be 56 [2] bc 57 [2] a7 51 [2] bb 56 [2] a7 79 }

  condition:
    any of them
}