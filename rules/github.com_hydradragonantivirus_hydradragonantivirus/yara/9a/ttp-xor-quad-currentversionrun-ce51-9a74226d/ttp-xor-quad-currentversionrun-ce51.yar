rule TTP_XOR_QUAD_CurrentVersionRun_ce51 {
  strings:
    $key_ce51 = { 9d 3e [2] b9 30 [2] 92 1c [2] bc 3e [2] a8 25 [2] a7 3f [2] b9 22 [2] bb 23 [2] a0 25 [2] bc 22 [2] a0 0d }

  condition:
    any of them
}