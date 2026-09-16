rule TTP_XOR_QUAD_CurrentVersionRun_c900 {
  strings:
    $key_c900 = { 9a 6f [2] be 61 [2] 95 4d [2] bb 6f [2] af 74 [2] a0 6e [2] be 73 [2] bc 72 [2] a7 74 [2] bb 73 [2] a7 5c }

  condition:
    any of them
}