rule TTP_XOR_QUAD_CurrentVersionRun_ce6c {
  strings:
    $key_ce6c = { 9d 03 [2] b9 0d [2] 92 21 [2] bc 03 [2] a8 18 [2] a7 02 [2] b9 1f [2] bb 1e [2] a0 18 [2] bc 1f [2] a0 30 }

  condition:
    any of them
}