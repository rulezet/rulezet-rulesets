rule TTP_XOR_QUAD_CurrentVersionRun_ce5d {
  strings:
    $key_ce5d = { 9d 32 [2] b9 3c [2] 92 10 [2] bc 32 [2] a8 29 [2] a7 33 [2] b9 2e [2] bb 2f [2] a0 29 [2] bc 2e [2] a0 01 }

  condition:
    any of them
}