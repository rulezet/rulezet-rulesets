rule TTP_XOR_QUAD_CurrentVersionRun_ce21 {
  strings:
    $key_ce21 = { 9d 4e [2] b9 40 [2] 92 6c [2] bc 4e [2] a8 55 [2] a7 4f [2] b9 52 [2] bb 53 [2] a0 55 [2] bc 52 [2] a0 7d }

  condition:
    any of them
}