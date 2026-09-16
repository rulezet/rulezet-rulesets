rule TTP_XOR_QUAD_CurrentVersionRun_ceff {
  strings:
    $key_ceff = { 9d 90 [2] b9 9e [2] 92 b2 [2] bc 90 [2] a8 8b [2] a7 91 [2] b9 8c [2] bb 8d [2] a0 8b [2] bc 8c [2] a0 a3 }

  condition:
    any of them
}