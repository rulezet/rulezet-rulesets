rule TTP_XOR_QUAD_CurrentVersionRun_ce60 {
  strings:
    $key_ce60 = { 9d 0f [2] b9 01 [2] 92 2d [2] bc 0f [2] a8 14 [2] a7 0e [2] b9 13 [2] bb 12 [2] a0 14 [2] bc 13 [2] a0 3c }

  condition:
    any of them
}