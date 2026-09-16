rule TTP_XOR_QUAD_CurrentVersionRun_c901 {
  strings:
    $key_c901 = { 9a 6e [2] be 60 [2] 95 4c [2] bb 6e [2] af 75 [2] a0 6f [2] be 72 [2] bc 73 [2] a7 75 [2] bb 72 [2] a7 5d }

  condition:
    any of them
}