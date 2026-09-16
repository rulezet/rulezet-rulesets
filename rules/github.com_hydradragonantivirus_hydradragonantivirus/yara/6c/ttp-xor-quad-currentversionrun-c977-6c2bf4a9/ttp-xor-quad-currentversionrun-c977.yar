rule TTP_XOR_QUAD_CurrentVersionRun_c977 {
  strings:
    $key_c977 = { 9a 18 [2] be 16 [2] 95 3a [2] bb 18 [2] af 03 [2] a0 19 [2] be 04 [2] bc 05 [2] a7 03 [2] bb 04 [2] a7 2b }

  condition:
    any of them
}