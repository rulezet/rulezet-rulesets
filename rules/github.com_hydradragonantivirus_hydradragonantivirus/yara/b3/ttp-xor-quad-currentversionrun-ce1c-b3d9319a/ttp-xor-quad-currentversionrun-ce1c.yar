rule TTP_XOR_QUAD_CurrentVersionRun_ce1c {
  strings:
    $key_ce1c = { 9d 73 [2] b9 7d [2] 92 51 [2] bc 73 [2] a8 68 [2] a7 72 [2] b9 6f [2] bb 6e [2] a0 68 [2] bc 6f [2] a0 40 }

  condition:
    any of them
}