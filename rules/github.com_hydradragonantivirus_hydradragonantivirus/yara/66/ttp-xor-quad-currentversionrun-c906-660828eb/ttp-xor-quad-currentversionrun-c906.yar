rule TTP_XOR_QUAD_CurrentVersionRun_c906 {
  strings:
    $key_c906 = { 9a 69 [2] be 67 [2] 95 4b [2] bb 69 [2] af 72 [2] a0 68 [2] be 75 [2] bc 74 [2] a7 72 [2] bb 75 [2] a7 5a }

  condition:
    any of them
}