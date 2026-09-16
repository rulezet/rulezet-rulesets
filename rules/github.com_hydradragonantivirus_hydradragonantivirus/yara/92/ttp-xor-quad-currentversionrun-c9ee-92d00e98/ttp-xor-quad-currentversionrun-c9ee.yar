rule TTP_XOR_QUAD_CurrentVersionRun_c9ee {
  strings:
    $key_c9ee = { 9a 81 [2] be 8f [2] 95 a3 [2] bb 81 [2] af 9a [2] a0 80 [2] be 9d [2] bc 9c [2] a7 9a [2] bb 9d [2] a7 b2 }

  condition:
    any of them
}