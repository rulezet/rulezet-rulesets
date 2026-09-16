rule TTP_XOR_QUAD_CurrentVersionRun_c9e2 {
  strings:
    $key_c9e2 = { 9a 8d [2] be 83 [2] 95 af [2] bb 8d [2] af 96 [2] a0 8c [2] be 91 [2] bc 90 [2] a7 96 [2] bb 91 [2] a7 be }

  condition:
    any of them
}