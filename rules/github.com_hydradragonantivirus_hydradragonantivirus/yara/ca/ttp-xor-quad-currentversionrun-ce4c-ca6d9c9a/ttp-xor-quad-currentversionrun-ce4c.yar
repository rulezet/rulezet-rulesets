rule TTP_XOR_QUAD_CurrentVersionRun_ce4c {
  strings:
    $key_ce4c = { 9d 23 [2] b9 2d [2] 92 01 [2] bc 23 [2] a8 38 [2] a7 22 [2] b9 3f [2] bb 3e [2] a0 38 [2] bc 3f [2] a0 10 }

  condition:
    any of them
}