rule TTP_XOR_QUAD_CurrentVersionRun_d50c {
  strings:
    $key_d50c = { 86 63 [2] a2 6d [2] 89 41 [2] a7 63 [2] b3 78 [2] bc 62 [2] a2 7f [2] a0 7e [2] bb 78 [2] a7 7f [2] bb 50 }

  condition:
    any of them
}