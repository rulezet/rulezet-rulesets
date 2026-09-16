rule TTP_XOR_QUAD_CurrentVersionRun_d57d {
  strings:
    $key_d57d = { 86 12 [2] a2 1c [2] 89 30 [2] a7 12 [2] b3 09 [2] bc 13 [2] a2 0e [2] a0 0f [2] bb 09 [2] a7 0e [2] bb 21 }

  condition:
    any of them
}