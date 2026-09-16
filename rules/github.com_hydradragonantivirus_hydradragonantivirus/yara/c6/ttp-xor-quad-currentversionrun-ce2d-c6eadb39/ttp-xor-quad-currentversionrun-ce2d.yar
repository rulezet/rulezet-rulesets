rule TTP_XOR_QUAD_CurrentVersionRun_ce2d {
  strings:
    $key_ce2d = { 9d 42 [2] b9 4c [2] 92 60 [2] bc 42 [2] a8 59 [2] a7 43 [2] b9 5e [2] bb 5f [2] a0 59 [2] bc 5e [2] a0 71 }

  condition:
    any of them
}