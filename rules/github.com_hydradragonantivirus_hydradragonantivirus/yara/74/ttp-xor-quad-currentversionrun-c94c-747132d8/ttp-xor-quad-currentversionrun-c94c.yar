rule TTP_XOR_QUAD_CurrentVersionRun_c94c {
  strings:
    $key_c94c = { 9a 23 [2] be 2d [2] 95 01 [2] bb 23 [2] af 38 [2] a0 22 [2] be 3f [2] bc 3e [2] a7 38 [2] bb 3f [2] a7 10 }

  condition:
    any of them
}