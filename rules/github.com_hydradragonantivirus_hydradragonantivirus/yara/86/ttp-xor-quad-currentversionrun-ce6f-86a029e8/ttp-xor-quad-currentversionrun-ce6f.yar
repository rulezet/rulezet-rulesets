rule TTP_XOR_QUAD_CurrentVersionRun_ce6f {
  strings:
    $key_ce6f = { 9d 00 [2] b9 0e [2] 92 22 [2] bc 00 [2] a8 1b [2] a7 01 [2] b9 1c [2] bb 1d [2] a0 1b [2] bc 1c [2] a0 33 }

  condition:
    any of them
}