rule TTP_XOR_QUAD_CurrentVersionRun_c911 {
  strings:
    $key_c911 = { 9a 7e [2] be 70 [2] 95 5c [2] bb 7e [2] af 65 [2] a0 7f [2] be 62 [2] bc 63 [2] a7 65 [2] bb 62 [2] a7 4d }

  condition:
    any of them
}