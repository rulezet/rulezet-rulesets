rule TTP_XOR_QUAD_CurrentVersionRun_ce80 {
  strings:
    $key_ce80 = { 9d ef [2] b9 e1 [2] 92 cd [2] bc ef [2] a8 f4 [2] a7 ee [2] b9 f3 [2] bb f2 [2] a0 f4 [2] bc f3 [2] a0 dc }

  condition:
    any of them
}