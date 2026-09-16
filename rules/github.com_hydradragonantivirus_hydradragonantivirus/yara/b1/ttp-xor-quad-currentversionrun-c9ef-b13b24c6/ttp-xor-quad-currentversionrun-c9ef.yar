rule TTP_XOR_QUAD_CurrentVersionRun_c9ef {
  strings:
    $key_c9ef = { 9a 80 [2] be 8e [2] 95 a2 [2] bb 80 [2] af 9b [2] a0 81 [2] be 9c [2] bc 9d [2] a7 9b [2] bb 9c [2] a7 b3 }

  condition:
    any of them
}