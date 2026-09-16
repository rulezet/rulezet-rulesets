rule TTP_XOR_QUAD_CurrentVersionRun_ce62 {
  strings:
    $key_ce62 = { 9d 0d [2] b9 03 [2] 92 2f [2] bc 0d [2] a8 16 [2] a7 0c [2] b9 11 [2] bb 10 [2] a0 16 [2] bc 11 [2] a0 3e }

  condition:
    any of them
}